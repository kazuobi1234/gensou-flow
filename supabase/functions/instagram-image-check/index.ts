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

const expectedHost="lkynzlittlxhbpvnuajw.supabase.co";
Deno.serve(async(req:Request)=>{
 if(req.method==="OPTIONS")return new Response(null,{status:204,headers:cors});
 if(req.method!=="POST")return reply({ok:false,error:"Method not allowed"},405);
 try{
  if(!await verifyOwner(req))return reply({ok:false,error:"Unauthorized"},401);
  const data=await req.json();
  if(data?.action!=="check_image")return reply({ok:false,error:"Read-only check only"},403);
  const raw=typeof data.image_url==="string"?data.image_url.trim():"";
  let u:URL;
  try{u=new URL(raw)}catch{return reply({ok:true,ready:false,reason:raw.length===0?"URL is empty":"Invalid URL",input_length:raw.length,published:false})}
  if(u.protocol!=="https:"||u.hostname!==expectedHost||!u.pathname.startsWith("/storage/v1/object/public/instagram-posts/")||u.username||u.password||u.search||u.hash)
   return reply({ok:true,ready:false,reason:"Use a public instagram-posts object URL",published:false});
  const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),9000);
  let response:Response;try{response=await fetch(u.toString(),{method:"GET",headers:{Range:"bytes=0-0"},signal:controller.signal,redirect:"error"})}finally{clearTimeout(timer)}
  const mime=(response.headers.get("content-type")||"").split(";")[0].toLowerCase();
  const supported=["image/jpeg"].includes(mime);
  const lengthHeader=response.headers.get("content-range")||"";
  const totalMatch=lengthHeader.match(/\/(\d+)$/);
  const size=totalMatch?Number(totalMatch[1]):null;
  const ready=response.ok&&supported&&size!==null&&size<=8000000;
  const reason=!response.ok?"Image not accessible":!supported?"JPEG required":size===null?"Image size not verified":size>8000000?"Image too large":"OK";
  const db=getAdmin();const uid=Deno.env.get("ALLOWED_FIREBASE_UID")!;
  await db.from("instagram_publish_audit").insert({owner_uid:uid,event_type:"image_checked",outcome:ready?"ok":"rejected",details:{mime,http_status:response.status,size,ready,reason}});
  return reply({ok:true,ready,reason,mime,http_status:response.status,size,published:false});
 }catch(e){return reply({ok:false,ready:false,error:"Image inspection failed",published:false},502)}
});