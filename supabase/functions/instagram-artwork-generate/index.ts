import { decodeProtectedHeader, importX509, jwtVerify } from "npm:jose@5.9.6";
import { createClient } from "npm:@supabase/supabase-js@2.57.4";
const cors={"Access-Control-Allow-Origin":"https://kazuobi1234.github.io","Access-Control-Allow-Headers":"authorization, content-type","Access-Control-Allow-Methods":"POST, OPTIONS","Content-Type":"application/json"};
const reply=(v:unknown,s=200)=>new Response(JSON.stringify(v),{status:s,headers:cors});
async function auth(req:Request){
 const h=req.headers.get("Authorization")||"";
 if(!h.startsWith("Bearer "))return false;
 const {kid,alg}=decodeProtectedHeader(h.slice(7));
 if(!kid||alg!=="RS256")return false;
 const r=await fetch("https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com");
 if(!r.ok)throw Error("Firebase key lookup failed");
 const cert=(await r.json())[kid];if(!cert)return false;
 const {payload}=await jwtVerify(h.slice(7),await importX509(cert,"RS256"),{audience:"gensou-flow",issuer:"https://securetoken.google.com/gensou-flow"});
 const uid=Deno.env.get("ALLOWED_FIREBASE_UID");
 return !!uid&&payload.sub===uid;
}
function admin(){
 const keys=JSON.parse(Deno.env.get("SUPABASE_SECRET_KEYS")||"{}");
 const key=keys.default||Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
 if(!key)throw Error("Storage credentials not configured");
 return createClient(Deno.env.get("SUPABASE_URL")!,key,{auth:{persistSession:false}});
}
Deno.serve(async(req:Request)=>{
 if(req.method==="OPTIONS")return new Response(null,{status:204,headers:cors});
 if(req.method!=="POST")return reply({ok:false,error:"Method not allowed"},405);
 try{
  if(!await auth(req))return reply({ok:false,error:"Unauthorized"},401);
  const d=await req.json().catch(()=>({}));
  const account=Deno.env.get("CLOUDFLARE_ACCOUNT_ID")||"";
  const token=Deno.env.get("CLOUDFLARE_WORKERS_AI_TOKEN")||"";
  if(d.action==="status")return reply({ok:true,configured:!!account&&!!token,provider:"cloudflare-workers-ai",model:"@cf/black-forest-labs/flux-1-schnell",requires_final_publish_confirmation:true});
  if(d.action!=="generate")return reply({ok:false,error:"Unsupported action"},400);
  if(!account||!token)return reply({ok:false,error:"画像生成APIの接続設定がまだ完了していません。Cloudflareの無料プラン用Account IDとWorkers AI API Tokenが必要です。",code:"provider_not_configured"},503);
  const prompt=typeof d.prompt==="string"?d.prompt.trim():"";
  if(prompt.length<20||prompt.length>1500)return reply({ok:false,error:"20〜1500文字の画像生成指示が必要です"},400);
  const seed=Number.isInteger(d.seed)&&d.seed>=0&&d.seed<2147483647?d.seed:crypto.getRandomValues(new Uint32Array(1))[0]%2147483647;
  const controller=new AbortController();const timeout=setTimeout(()=>controller.abort(),45000);
  let image="";
  try{
   const response=await fetch("https://api.cloudflare.com/client/v4/accounts/"+encodeURIComponent(account)+"/ai/run/@cf/black-forest-labs/flux-1-schnell",{
    method:"POST",headers:{"Authorization":"Bearer "+token,"Content-Type":"application/json"},
    body:JSON.stringify({prompt,steps:4,seed}),signal:controller.signal
   });
   if(!response.ok){console.error("Cloudflare image generation HTTP",response.status);return reply({ok:false,error:response.status===401||response.status===403?"Cloudflare画像AIの認証が拒否されました（HTTP "+response.status+"）。サーバー側のAPIトークン・権限を確認してください。秘密情報はチャットに貼らないでください。":response.status===429?"無料枠・生成回数の制限に達した可能性があります":"画像生成APIに失敗しました（HTTP "+response.status+"）",code:"provider_error"},502);}
   const data=await response.json();
   image=data?.result?.image||data?.image||"";
   if(data?.success===false||!image)return reply({ok:false,error:"画像生成結果を取得できませんでした",code:"missing_image"},502);
  }finally{clearTimeout(timeout);}
  if(image.length>14000000||!/^[A-Za-z0-9+/_=-]+$/.test(image))return reply({ok:false,error:"画像形式またはサイズが不正です"},502);
  const binary=atob(image.replace(/^data:image\/\w+;base64,/,""));
  const bytes=Uint8Array.from(binary,c=>c.charCodeAt(0));
  if(bytes.length<1000||bytes.length>10*1024*1024)return reply({ok:false,error:"画像サイズが不正です"},502);
  // FLUX.1 schnell returns JPEG, stored in the same private-write/public-read bucket.
  const png=bytes[0]===0x89&&bytes[1]===0x50&&bytes[2]===0x4e&&bytes[3]===0x47;
  const jpeg=bytes[0]===0xff&&bytes[1]===0xd8&&bytes[2]===0xff;
  if(!png&&!jpeg)return reply({ok:false,error:"画像のデータ形式を判定できません"},502);
  const mime=png?"image/png":"image/jpeg";
  const path="ai-drafts/"+crypto.randomUUID()+(png?".png":".jpg");
  const sb=admin();
  const {error}=await sb.storage.from("instagram-posts").upload(path,bytes,{contentType:mime,upsert:false});
  if(error)throw error;
  const {data}=sb.storage.from("instagram-posts").getPublicUrl(path);
  return reply({ok:true,image_url:data.publicUrl,seed,model:"flux-1-schnell",published:false});
 }catch(e){console.error("AI draft generation failed",e instanceof Error?e.message:String(e));return reply({ok:false,error:"画像制作処理に失敗しました。再実行前に状態を確認してください。"},500);}
});