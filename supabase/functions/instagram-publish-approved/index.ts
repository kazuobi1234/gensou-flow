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

Deno.serve(async(req:Request)=>{
 if(req.method==="OPTIONS")return new Response(null,{status:204,headers:cors});
 if(req.method!=="POST")return reply({ok:false,error:"method"},405);
 try{
  if(!await verifyOwner(req))return reply({ok:false,error:"Unauthorized"},401);
  const body=await req.json().catch(()=>({}));
  const db=getAdmin(),owner=Deno.env.get("ALLOWED_FIREBASE_UID")!;
  if(body.action==="status")return reply({ok:true,live_publish_enabled:true,requires_confirmation:true,published:false});
  if(body.action!=="publish"||body.confirmation!=="この承認済み投稿をInstagramに公開する")return reply({ok:false,error:"Explicit publication confirmation required",published:false},403);
  const key=String(body.request_key||""),project=String(body.project_id||"");
  if(!/^[0-9a-f-]{36}$/i.test(key)||!project||project==="instagram-diagnostic")return reply({ok:false,error:"Invalid request",published:false},400);
  const {data:record,error:loadError}=await db.from("instagram_publish_intents").select("status,caption,image_url,project_id,content_sha256,provider_media_id").eq("owner_uid",owner).eq("request_key",key).maybeSingle();
  if(loadError)throw loadError;
  if(!record||record.project_id!==project)return reply({ok:false,error:"Approved intent missing",published:false},404);
  if(record.status==="published")return reply({ok:true,published:true,already_published:true,media_id:record.provider_media_id});
  if(record.status!=="approved")return reply({ok:false,error:"Not approved or already claimed",published:false},409);
  const image=new URL(record.image_url);
  if(image.protocol!=="https:"||image.hostname!=="lkynzlittlxhbpvnuajw.supabase.co"||!image.pathname.startsWith("/storage/v1/object/public/instagram-posts/")||!image.pathname.toLowerCase().endsWith(".jpg"))return reply({ok:false,error:"Approved JPEG public image URL required",published:false},400);
  const storedHash=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(JSON.stringify([project,record.caption,record.image_url])));
  const hash=Array.from(new Uint8Array(storedHash)).map(x=>x.toString(16).padStart(2,"0")).join("");
  if(hash!==record.content_sha256)return reply({ok:false,error:"Integrity check failed",published:false},409);
  const id=Deno.env.get("INSTAGRAM_USER_ID"),token=Deno.env.get("INSTAGRAM_ACCESS_TOKEN");
  if(!id||!token)return reply({ok:false,error:"Instagram server configuration missing",published:false},503);
  const {data:claim,error:claimError}=await db.from("instagram_publish_intents").update({status:"publishing",claim_at:new Date().toISOString()}).eq("owner_uid",owner).eq("request_key",key).eq("status","approved").select("id").maybeSingle();
  if(claimError)throw claimError;
  if(!claim)return reply({ok:false,error:"Request has already been claimed",published:false},409);
  async function call(path:string,params:Record<string,string>){
   const res=await fetch("https://graph.instagram.com/v26.0/"+path,{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:new URLSearchParams({...params,access_token:token!}),signal:AbortSignal.timeout(30000)});
   const result=await res.json().catch(()=>({}));return {ok:res.ok,id:typeof result.id==="string"?result.id:null,status:res.status,code:result.error?.code||null};
  }
  const container=await call(id+"/media",{image_url:record.image_url,caption:record.caption});
  if(!container.ok||!container.id)return reply({ok:false,error:"Meta container creation failed; locked to prevent duplicates",stage:"container",meta_status:container.status,published:false},502);
  let ready=false;
  for(let n=0;n<4;n++){
   const r=await fetch("https://graph.instagram.com/v26.0/"+container.id+"?fields=status_code",{headers:{Authorization:"Bearer "+token},signal:AbortSignal.timeout(15000)});
   const state=await r.json().catch(()=>({}));
   if(r.ok&&state.status_code==="FINISHED"){ready=true;break;}
   if(state.status_code==="ERROR"||state.status_code==="EXPIRED")break;
   await new Promise(resolve=>setTimeout(resolve,1200));
  }
  if(!ready)return reply({ok:false,error:"Container not ready; no automatic retry to prevent duplicates",published:false},409);
  const published=await call(id+"/media_publish",{creation_id:container.id});
  if(!published.ok||!published.id)return reply({ok:false,error:"Meta publication unconfirmed; locked to prevent duplicates",meta_status:published.status,published:false},502);
  const {error:saveError}=await db.from("instagram_publish_intents").update({status:"published",published_at:new Date().toISOString(),provider_media_id:published.id}).eq("owner_uid",owner).eq("request_key",key).eq("status","publishing");
  if(saveError)console.error("Published, status save error",saveError.code);
  await db.from("instagram_publish_audit").insert({owner_uid:owner,request_key:key,event_type:"publish",outcome:"ok",provider_media_id:published.id});
  return reply({ok:true,published:true,media_id:published.id});
 }catch(e){console.error("Publish operation failed",e instanceof Error?e.message:"unknown");return reply({ok:false,error:"Publication state requires review before retry",published:false},500)}
});
