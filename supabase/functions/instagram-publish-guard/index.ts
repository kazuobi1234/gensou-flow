import { createClient } from "npm:@supabase/supabase-js@2.57.4";
import { decodeProtectedHeader, importX509, jwtVerify } from "npm:jose@5.9.6";

const cors = {
  "Access-Control-Allow-Origin": "https://kazuobi1234.github.io",
  "Access-Control-Allow-Headers": "authorization, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};
const reply = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: cors });

async function verifyOwner(req: Request) {
  const header = req.headers.get("Authorization") || "";
  if (!header.startsWith("Bearer ")) return false;
  const token = header.slice(7);
  const { kid, alg } = decodeProtectedHeader(token);
  if (!kid || alg !== "RS256") return false;
  const certificates = await fetch(
    "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com",
  );
  if (!certificates.ok) throw new Error("Cannot fetch Firebase certificates");
  const cert = (await certificates.json())[kid];
  if (!cert) return false;
  const { payload } = await jwtVerify(
    token,
    await importX509(cert, "RS256"),
    {
      audience: "gensou-flow",
      issuer: "https://securetoken.google.com/gensou-flow",
    },
  );
  const allowedUID = Deno.env.get("ALLOWED_FIREBASE_UID");
  return !!allowedUID && payload.sub === allowedUID;
}

const getAdmin = () => {
 const secrets=JSON.parse(Deno.env.get("SUPABASE_SECRET_KEYS")||"{}");
 const key=secrets.default||Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
 if(!key)throw Error("Missing server storage credentials");
 return createClient(Deno.env.get("SUPABASE_URL")!,key,{auth:{persistSession:false}});
};
Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
  if (req.method !== "POST") return reply({ ok: false, error: "Method not allowed" }, 405);
  try {
    if (!(await verifyOwner(req))) return reply({ ok: false, error: "Unauthorized" }, 401);
    const data = await req.json();
    if (!data || !["validate","prepare","approve","dry_run_claim"].includes(data.action)) {
      return reply({ ok: false, error: "Publishing is disabled. Only validate is supported", published: false }, 403);
    }
    if(data.action==="dry_run_claim"){
      const key=typeof data.request_key==="string"?data.request_key:"";
      if(!/^[0-9a-f-]{36}$/i.test(key))return reply({ok:false,error:"Invalid key",published:false},400);
      const uid=Deno.env.get("ALLOWED_FIREBASE_UID")!;
      const db=getAdmin();
      const {data:record,error:readError}=await db.from("instagram_publish_intents")
        .select("project_id,status").eq("owner_uid",uid).eq("request_key",key).maybeSingle();
      if(readError)throw readError;
      if(!record || record.project_id!=="instagram-diagnostic")return reply({ok:false,error:"Test request not found",published:false},404);
      if(record.status!=="approved")return reply({ok:true,claimed:false,already_claimed:record.status==="dry_run_claimed",status:record.status,published:false});
      const {data:claimed,error:claimError}=await db.from("instagram_publish_intents")
        .update({status:"dry_run_claimed",claim_at:new Date().toISOString()})
        .eq("owner_uid",uid).eq("request_key",key).eq("project_id","instagram-diagnostic").eq("status","approved")
        .select("id").maybeSingle();
      if(claimError)throw claimError;
      const {error:auditError}=await db.from("instagram_publish_audit").insert({owner_uid:uid,request_key:key,event_type:"dry_run_result",outcome:claimed?"ok":"rejected",details:{claimed:!!claimed,already_claimed:!claimed}});
      if(auditError)console.error("audit insert failed",auditError.code);
            return reply({ok:true,claimed:!!claimed,already_claimed:!claimed,published:false,note:"Dry run only, no Instagram API call"});
    }
    if(data.action==="approve"){
      const key=typeof data.request_key==="string"?data.request_key:"";
      const project=typeof data.project_id==="string"?data.project_id.trim():"";
      const confirmation=data.confirmation;
      if(confirmation!=="この投稿内容を承認する" || !project || !/^[0-9a-f-]{36}$/i.test(key))
        return reply({ok:false,error:"Explicit confirmation and valid project/request key required",published:false},400);
      const db=getAdmin();
      const uid=Deno.env.get("ALLOWED_FIREBASE_UID")!;
      const {data:record,error:readError}=await db.from("instagram_publish_intents")
        .select("id,project_id,caption,image_url,content_sha256,status")
        .eq("owner_uid",uid).eq("request_key",key).maybeSingle();
      if(readError)throw readError;
      if(!record || record.project_id!==project)
        return reply({ok:false,error:"No matching prepared request",published:false},404);
      const caption=typeof data.caption==="string"?data.caption.trim():"";
      const imageUrl=typeof data.image_url==="string"?data.image_url.trim():"";
      const input=new TextEncoder().encode(JSON.stringify([project,caption,imageUrl]));
      const digest=Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",input))).map(b=>b.toString(16).padStart(2,"0")).join("");
      if(digest!==record.content_sha256)return reply({ok:false,error:"Content has changed; create a new request",published:false},409);
      if(record.status==="approved")return reply({ok:true,approved:true,duplicate:true,published:false,request_key:key});
      if(record.status!=="prepared")return reply({ok:false,error:"Request cannot be approved in current state",published:false},409);
      const {data:updated,error:updateError}=await db.from("instagram_publish_intents")
        .update({status:"approved",approved_at:new Date().toISOString()})
        .eq("owner_uid",uid).eq("request_key",key).eq("status","prepared")
        .select("id").maybeSingle();
      if(updateError)throw updateError;
      if(!updated)return reply({ok:false,error:"Request was changed concurrently",published:false},409);
      return reply({ok:true,approved:true,request_key:key,published:false,note:"サーバー側に承認を記録しました。Instagramには公開していません。"});
    }
    const errors: string[] = [];
    const caption = typeof data.caption === "string" ? data.caption.trim() : "";
    const imageUrl = typeof data.image_url === "string" ? data.image_url.trim() : "";
    if (!caption) errors.push("投稿文が未入力です");
    if (caption.length > 2200) errors.push("投稿文は2200文字以内にしてください");
    if (!imageUrl) errors.push("画像URLが未入力です");
    if (imageUrl) {
      try {
        const u = new URL(imageUrl);
        if (u.protocol !== "https:" || u.username || u.password)
          errors.push("画像URLは認証情報のないHTTPSのみ対応です");
      } catch {
        errors.push("画像URLの形式が不正です");
      }
    }
    if(data.action==="prepare" && errors.length===0){
      const projectId=typeof data.project_id==="string"?data.project_id.trim():"";
      const key=typeof data.request_key==="string"?data.request_key:"";
      if(!projectId||projectId.length>150||!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(key))return reply({ok:false,error:"Invalid project or request key",published:false},400);
      const encoder=new TextEncoder();
      const bytes=encoder.encode(JSON.stringify([projectId,caption,imageUrl]));
      const hash=Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",bytes))).map(b=>b.toString(16).padStart(2,"0")).join("");
      const ownerUID=Deno.env.get("ALLOWED_FIREBASE_UID")!;
      const db=getAdmin();
      const {data:existing,error:readErr}=await db.from("instagram_publish_intents").select("id,content_sha256,status").eq("owner_uid",ownerUID).eq("request_key",key).maybeSingle();
      if(readErr)throw readErr;
      if(existing){
        if(existing.content_sha256!==hash)return reply({ok:false,error:"Request key already used with different content",published:false},409);
        return reply({ok:true,prepared:true,request_key:key,status:existing.status,duplicate:true,published:false});
      }
      const {error:insertErr}=await db.from("instagram_publish_intents").insert({owner_uid:ownerUID,request_key:key,project_id:projectId,caption,image_url:imageUrl,content_sha256:hash,status:"prepared"});
      if(insertErr){if(insertErr.code==="23505")return reply({ok:false,error:"Request already registered; retry status lookup",published:false},409);throw insertErr;}
      return reply({ok:true,prepared:true,request_key:key,status:"prepared",published:false});
    }
    return reply({
      ok: true,
      ready: errors.length === 0,
      errors,
      published: false,
      note: "形式確認のみ。サーバー承認照合・Metaへの公開・画像取得は実施していません。",
    });
  } catch (e) {
    console.error("instagram publish guard", e instanceof Error ? e.message : String(e));
    return reply({ ok: false, error: "Validation failed", published: false }, 400);
  }
});
