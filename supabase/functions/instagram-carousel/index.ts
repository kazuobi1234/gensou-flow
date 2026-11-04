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

const validImage=(url:string)=>{
 try{const u=new URL(url);return u.protocol==="https:"&&u.hostname==="lkynzlittlxhbpvnuajw.supabase.co"&&u.pathname.startsWith("/storage/v1/object/public/instagram-posts/")&&/\.jpe?g$/i.test(u.pathname)&&!u.username&&!u.password&&!u.search;}catch{return false}
};
const fingerprint=async(project:string,caption:string,urls:string[])=>{
 const bytes=new TextEncoder().encode(JSON.stringify([project,caption,urls]));
 return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",bytes))).map(n=>n.toString(16).padStart(2,"0")).join("");
};
Deno.serve(async(req:Request)=>{
 if(req.method==="OPTIONS")return new Response(null,{status:204,headers:cors});
 if(req.method!=="POST")return reply({ok:false,error:"Method not allowed"},405);
 try{
  if(!await verifyOwner(req))return reply({ok:false,error:"Unauthorized"},401);
  const d=await req.json().catch(()=>({}));const action=d.action;
  if(!["prepare","approve","status","publish"].includes(action))return reply({ok:false,error:"Unsupported action"},400);
  const uid=Deno.env.get("ALLOWED_FIREBASE_UID")!;
  const key=typeof d.request_key==="string"?d.request_key:"",project=typeof d.project_id==="string"?d.project_id:"";
  if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(key)||!project||project==="instagram-diagnostic"||project.length>150)return reply({ok:false,error:"Invalid request"},400);
  const db=getAdmin();
  const {data:old,error:loadError}=await db.from("instagram_carousel_intents").select("*").eq("owner_uid",uid).eq("request_key",key).maybeSingle();
  if(loadError)throw loadError;
  if(action==="status")return reply({ok:true,status:old?.status||"not_found",published:old?.status==="published",media_id:old?.provider_media_id||null});
  if(action==="prepare"){
   const urls=d.image_urls,caption=typeof d.caption==="string"?d.caption.trim():"";
   if(!Array.isArray(urls)||urls.length!==5||!urls.every((u:unknown)=>typeof u==="string"&&validImage(u))||new Set(urls).size!==5||caption.length<1||caption.length>2200)return reply({ok:false,error:"Five distinct public JPEG URLs and valid caption required",published:false},400);
   const hash=await fingerprint(project,caption,urls);
   if(old)return reply({ok:old.content_sha256===hash,prepared:old.content_sha256===hash,status:old.status,request_key:key,published:old.status==="published"});
   const {error}=await db.from("instagram_carousel_intents").insert({owner_uid:uid,request_key:key,project_id:project,caption,image_urls:urls,content_sha256:hash,status:"prepared"});
   if(error)throw error;
   return reply({ok:true,prepared:true,published:false,request_key:key});
  }
  if(!old||old.project_id!==project)return reply({ok:false,error:"Request not found",published:false},404);
  if(action==="approve"){
   const urls=d.image_urls,caption=typeof d.caption==="string"?d.caption.trim():"";
   if(d.confirmation!=="このカルーセル投稿の5枚と文章を承認する"||!Array.isArray(urls)||await fingerprint(project,caption,urls)!==old.content_sha256)return reply({ok:false,error:"Confirmation or content mismatch",published:false},409);
   if(old.status==="approved")return reply({ok:true,approved:true,published:false});
   if(old.status!=="prepared")return reply({ok:false,error:"Not awaiting approval",published:false},409);
   const {data:changed,error}=await db.from("instagram_carousel_intents").update({status:"approved",approved_at:new Date().toISOString()}).eq("owner_uid",uid).eq("request_key",key).eq("status","prepared").select("id").maybeSingle();if(error)throw error;
   return reply({ok:!!changed,approved:!!changed,published:false});
  }
  if(d.confirmation!=="この承認済みの5枚をInstagramに公開する")return reply({ok:false,error:"Final explicit publication confirmation required",published:false},403);
  if(old.status==="published")return reply({ok:true,published:true,already_published:true,media_id:old.provider_media_id});
  if(old.status!=="approved")return reply({ok:false,error:"Not approved or already claimed; do not retry",published:false},409);
  const urls=old.image_urls as string[];
  if(urls.length!==5||!urls.every(validImage)||new Set(urls).size!==5||await fingerprint(project,old.caption,urls)!==old.content_sha256)return reply({ok:false,error:"Content integrity check failed",published:false},409);
  const account=Deno.env.get("INSTAGRAM_USER_ID"),token=Deno.env.get("INSTAGRAM_ACCESS_TOKEN");
  if(!account||!token)return reply({ok:false,error:"Instagram connection unavailable",published:false},503);
  const {data:claim,error:claimError}=await db.from("instagram_carousel_intents").update({status:"publishing",claim_at:new Date().toISOString()}).eq("owner_uid",uid).eq("request_key",key).eq("status","approved").select("id").maybeSingle();
  if(claimError)throw claimError;if(!claim)return reply({ok:false,error:"Request already claimed",published:false},409);
  const post=async(path:string,payload:Record<string,string>)=>{
    const resp=await fetch("https://graph.instagram.com/v26.0/"+path,{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:new URLSearchParams({...payload,access_token:token}),signal:AbortSignal.timeout(25000)});
    const json=await resp.json().catch(()=>({}));return {ok:resp.ok,id:typeof json.id==="string"?json.id:null,status:resp.status,code:json.error?.code||null};
  };
  const poll=async(id:string)=>{
   for(let i=0;i<6;i++){
    const resp=await fetch("https://graph.instagram.com/v26.0/"+encodeURIComponent(id)+"?fields=status_code",{headers:{Authorization:"Bearer "+token},signal:AbortSignal.timeout(12000)});
    const json=await resp.json().catch(()=>({}));
    if(resp.ok&&json.status_code==="FINISHED")return true;
    if(json.status_code==="ERROR"||json.status_code==="EXPIRED")return false;
    await new Promise(done=>setTimeout(done,1500));
   }
   return false;
  };
  const children:string[]=[];
  for(const url of urls){
   const item=await post(account+"/media",{image_url:url,is_carousel_item:"true"});
   if(!item.ok||!item.id||!await poll(item.id))return reply({ok:false,error:"Carousel item preparation failed; request locked",stage:"child",published:false},502);
   children.push(item.id);
  }
  const carousel=await post(account+"/media",{media_type:"CAROUSEL",children:children.join(","),caption:old.caption});
  if(!carousel.ok||!carousel.id||!await poll(carousel.id))return reply({ok:false,error:"Carousel preparation failed; request locked",stage:"carousel",published:false},502);
  const result=await post(account+"/media_publish",{creation_id:carousel.id});
  if(!result.ok||!result.id)return reply({ok:false,error:"Meta publish not confirmed; do not retry",stage:"publish",published:false},502);
  const {error:saveError}=await db.from("instagram_carousel_intents").update({status:"published",published_at:new Date().toISOString(),provider_media_id:result.id}).eq("owner_uid",uid).eq("request_key",key).eq("status","publishing");
  if(saveError)console.error("Published but database update failed",saveError.code);
  await db.from("instagram_publish_audit").insert({owner_uid:uid,request_key:key,event_type:"carousel_publish",outcome:"ok",provider_media_id:result.id,details:{image_count:5}});
  return reply({ok:true,published:true,media_id:result.id});
 }catch(e){console.error("Carousel failed",e instanceof Error?e.message:"unknown");return reply({ok:false,error:"State uncertain; do not retry until reviewed",published:false},500)}
});
