import { decodeProtectedHeader, importX509, jwtVerify } from "npm:jose@5.9.6";
const cors={"Access-Control-Allow-Origin":"https://kazuobi1234.github.io","Access-Control-Allow-Headers":"authorization, content-type","Access-Control-Allow-Methods":"POST, OPTIONS","Content-Type":"application/json"};
const reply=(data:unknown,status=200)=>new Response(JSON.stringify(data),{status,headers:cors});
async function auth(req:Request){
 const bearer=req.headers.get("Authorization")||"";
 if(!bearer.startsWith("Bearer "))return false;
 const token=bearer.slice(7);
 const {kid,alg}=decodeProtectedHeader(token);
 if(!kid||alg!=="RS256")return false;
 const response=await fetch("https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com");
 if(!response.ok)throw Error("Firebase certs unavailable");
 const cert=(await response.json())[kid];
 if(!cert)return false;
 const {payload}=await jwtVerify(token,await importX509(cert,"RS256"),{audience:"gensou-flow",issuer:"https://securetoken.google.com/gensou-flow"});
 const allowed=Deno.env.get("ALLOWED_FIREBASE_UID");
 const now=Math.floor(Date.now()/1000);
 return !!allowed&&payload.sub===allowed&&typeof payload.iat==="number"&&payload.iat<=now&&typeof payload.auth_time==="number"&&payload.auth_time<=now;
}
Deno.serve(async(req:Request)=>{
 if(req.method==="OPTIONS")return new Response(null,{status:204,headers:cors});
 if(req.method!=="POST")return reply({ok:false,error:"Method not allowed"},405);
 try{
  if(!await auth(req))return reply({ok:false,error:"Unauthorized"},401);
  const body=await req.json();
  if(body.action!=="preview")return reply({ok:false,error:"Only preview supported; publication disabled"},400);
  const caption=typeof body.caption==="string"?body.caption.trim():"";
  const image_url=typeof body.image_url==="string"?body.image_url.trim():"";
  const errors:string[]=[];
  if(!caption)errors.push("投稿文が未入力です");
  if(!image_url)errors.push("画像の公開URLが未入力です");
  if(image_url){try{const u=new URL(image_url);if(u.protocol!=="https:"||u.username||u.password)errors.push("画像URLはHTTPSのみ対応です")}catch{errors.push("画像URLの形式が正しくありません")}}
  if(caption.length>2200)errors.push("投稿文は2200文字以内にしてください");
  return reply({ok:true,ready:errors.length===0,errors,preview:{caption,image_url},published:false,note:"入力形式のみ検証。画像取得・Instagram公開は未実行。"});
 }catch(e){console.error("approval preview",e instanceof Error?e.message:String(e));return reply({ok:false,error:"処理に失敗しました"},500)}
});