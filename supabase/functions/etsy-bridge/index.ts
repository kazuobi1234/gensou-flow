import { decodeProtectedHeader, importX509, jwtVerify } from "npm:jose@5.9.6";

import { createClient } from "npm:@supabase/supabase-js@2.57.4";
const redirect="https://kazuobi1234.github.io/gensou-flow/";
const uid=()=>Deno.env.get("ALLOWED_FIREBASE_UID")||"";
const db=()=>{const keys=JSON.parse(Deno.env.get("SUPABASE_SECRET_KEYS")||"{}");return createClient(Deno.env.get("SUPABASE_URL")!,keys.default||Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,{auth:{persistSession:false}})};
const b64=(x:Uint8Array)=>btoa(String.fromCharCode(...x)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const rand=(n:number)=>b64(crypto.getRandomValues(new Uint8Array(n)));
const aes=async()=>{const raw=Deno.env.get("ETSY_TOKEN_ENCRYPTION_KEY")||"";if(!/^[A-Za-z0-9_-]{43}$/.test(raw))throw Error("ETSY_TOKEN_ENCRYPTION_KEY not configured (32-byte base64url)");const bytes=Uint8Array.from(atob(raw.replace(/-/g,"+").replace(/_/g,"/")+"="),c=>c.charCodeAt(0));return crypto.subtle.importKey("raw",bytes,"AES-GCM",false,["encrypt","decrypt"])};
const encrypt=async(token:string)=>{const iv=crypto.getRandomValues(new Uint8Array(12));const buf=await crypto.subtle.encrypt({name:"AES-GCM",iv},await aes(),new TextEncoder().encode(token));return {token_cipher:b64(new Uint8Array(buf)),token_iv:b64(iv)}};
const dec=(x:string)=>Uint8Array.from(atob(x.replace(/-/g,"+").replace(/_/g,"/")+"=".repeat((4-x.length%4)%4)),c=>c.charCodeAt(0));
const decrypt=async(row:any)=>new TextDecoder().decode(await crypto.subtle.decrypt({name:"AES-GCM",iv:dec(row.token_iv)},await aes(),dec(row.token_cipher)));
async function oauthAction(action:string,body:any){
 const api=(Deno.env.get("ETSY_API_KEY")||"").split(":")[0];
 if(!api)return send({ok:false,error:"ETSY_API_KEY is not configured"},503);
 if(action==="begin"){
  const missing=["ETSY_TOKEN_ENCRYPTION_KEY"].filter(k=>!Deno.env.get(k));
  if(missing.length)return send({ok:false,error:"不足設定："+missing.join(", "),missing},503);
  await aes();
  const state=rand(32),verifier=rand(48),hash=new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(verifier)));
  const {error}=await db().from("etsy_oauth_connections").upsert({owner_uid:uid(),state,verifier,expires_at:new Date(Date.now()+600000).toISOString(),updated_at:new Date().toISOString()},{onConflict:"owner_uid"});
  if(error)throw Error("Unable to create authorization session");
  const u=new URL("https://www.etsy.com/oauth/connect");
  for(const [k,v] of Object.entries({response_type:"code",client_id:api,redirect_uri:redirect,scope:"shops_r listings_r listings_w transactions_r",state,code_challenge:b64(hash),code_challenge_method:"S256"}))u.searchParams.set(k,v);
  return send({ok:true,authorization_url:u.toString(),callback_url:redirect});
 }
 if(action==="complete"){
  const state=String(body.state||""),code=String(body.code||"");
  if(!/^[A-Za-z0-9_-]{40,100}$/.test(state)||code.length<5||code.length>400)return send({ok:false,error:"Invalid callback"},400);
  const {data:row,error}=await db().from("etsy_oauth_connections").select("*").eq("owner_uid",uid()).eq("state",state).maybeSingle();
  if(error||!row||!row.verifier||new Date(row.expires_at).getTime()<Date.now())return send({ok:false,error:"Expired or mismatched OAuth state"},409);
  // Consume before token exchange to prevent repeat exchanges.
  const {error:consumeErr}=await db().from("etsy_oauth_connections").update({state:null,verifier:null,expires_at:null}).eq("owner_uid",uid()).eq("state",state);
  if(consumeErr)throw Error("Unable to consume OAuth state");
  const r=await fetch("https://api.etsy.com/v3/public/oauth/token",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:new URLSearchParams({grant_type:"authorization_code",client_id:api,redirect_uri:redirect,code,code_verifier:row.verifier}),signal:AbortSignal.timeout(15000)});
  if(!r.ok)return send({ok:false,error:"Etsy token exchange failed",status:r.status},502);
  const t=await r.json();
  if(!t.refresh_token)return send({ok:false,error:"Etsy did not return a refresh token"},502);
  const secret=await encrypt(String(t.refresh_token));
  const {error:save}=await db().from("etsy_oauth_connections").update({...secret,connected_at:new Date().toISOString(),updated_at:new Date().toISOString()}).eq("owner_uid",uid());
  if(save)throw Error("Unable to securely save Etsy connection");
  return send({ok:true,connected:true});
 }
 return send({ok:false,error:"Unknown OAuth action"},400);
}

const cors={"Access-Control-Allow-Origin":"https://kazuobi1234.github.io","Access-Control-Allow-Headers":"authorization, content-type","Access-Control-Allow-Methods":"POST, OPTIONS","Content-Type":"application/json"};
const send=(data:unknown,status=200)=>new Response(JSON.stringify(data),{status,headers:cors});
async function owner(req:Request){
 const h=req.headers.get("authorization")||"";
 if(!h.startsWith("Bearer "))return false;
 const token=h.slice(7),{kid,alg}=decodeProtectedHeader(token);
 if(!kid||alg!=="RS256")return false;
 const r=await fetch("https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com");
 if(!r.ok)throw Error("Identity provider unavailable");
 const cert=(await r.json())[kid];if(!cert)return false;
 const {payload}=await jwtVerify(token,await importX509(cert,"RS256"),{audience:"gensou-flow",issuer:"https://securetoken.google.com/gensou-flow"});
 return !!Deno.env.get("ALLOWED_FIREBASE_UID")&&payload.sub===Deno.env.get("ALLOWED_FIREBASE_UID");
}
async function etsyAccess(apiKey:string,refresh:string){
 const response=await fetch("https://api.etsy.com/v3/public/oauth/token",{method:"POST",headers:{"content-type":"application/x-www-form-urlencoded"},body:new URLSearchParams({grant_type:"refresh_token",client_id:apiKey.split(":")[0],refresh_token:refresh}),signal:AbortSignal.timeout(12000)});
 if(!response.ok)throw Error("Etsy OAuth refresh failed ("+response.status+")");
 const d=await response.json();if(!d.access_token)throw Error("Etsy token response invalid");return String(d.access_token);
}
Deno.serve(async(req:Request)=>{
 if(req.method==="OPTIONS")return new Response(null,{status:204,headers:cors});
 if(req.method!=="POST")return send({error:"Method not allowed"},405);
 try{
  if(!await owner(req))return send({error:"Unauthorized"},401);
  const {action,...body}=await req.json().catch(()=>({}));
  if(["begin","complete"].includes(action))return await oauthAction(action,body);
  if(!["status","discover_shop","orders","draft","upload_file","upload_image","listing_status"].includes(action))return send({error:"Unknown action"},400);
  const key=Deno.env.get("ETSY_API_KEY")||"",refresh=Deno.env.get("ETSY_REFRESH_TOKEN")||"",shop=Deno.env.get("ETSY_SHOP_ID")||"";
  const {data:connection}=await db().from("etsy_oauth_connections").select("token_cipher,token_iv").eq("owner_uid",uid()).maybeSingle();
  const saved=Boolean(connection?.token_cipher&&connection?.token_iv);
  const ready=Boolean(key.includes(":")&&(refresh||saved));
  if(action==="status")return send({ok:true,configured:ready,oauth_connected:saved,missing:[...(!key.includes(":")?["ETSY_API_KEY に Keystring:Shared Secret が必要"]:[]),...(!Deno.env.get("ETSY_TOKEN_ENCRYPTION_KEY")?["ETSY_TOKEN_ENCRYPTION_KEY"]:[])],publishing_enabled:false});
  if(action==="discover_shop"){
   if(!key.includes(":")||!(refresh||saved))return send({ok:false,error:"Etsy API keystring:secret and OAuth connection required"},503);
   const access=await etsyAccess(key,refresh||(saved?await decrypt(connection):""));
   const userId=access.split(".")[0];
   if(!/^[1-9][0-9]{0,17}$/.test(userId))return send({ok:false,error:"Etsy user ID unavailable from access token"},502);
   const result=await fetch("https://api.etsy.com/v3/application/users/"+userId+"/shops",{headers:{"x-api-key":key,"Authorization":"Bearer "+access},signal:AbortSignal.timeout(12000)});
   if(!result.ok)return send({ok:false,error:"Etsy shop lookup failed",status:result.status},502);
   const shopData=await result.json();
   return send({ok:true,shop_id:shopData.shop_id||null,shop_name:shopData.shop_name||null,shop_found:!!shopData.shop_id});
  }
  if(!ready)return send({ok:false,error:"Etsy credentials are not configured",missing:["ETSY_API_KEY","ETSY_REFRESH_TOKEN","ETSY_SHOP_ID"].filter(k=>!Deno.env.get(k))},503);
  const token=await etsyAccess(key,refresh||(saved?await decrypt(connection):""));
  let actualShop=shop;
  if(!/^[0-9]+$/.test(actualShop)){
   const userId=token.split(".")[0];
   if(!/^[1-9][0-9]{0,17}$/.test(userId))return send({ok:false,error:"Etsy user ID missing"},502);
   const shopResponse=await fetch("https://api.etsy.com/v3/application/users/"+userId+"/shops",{headers:{"x-api-key":key},signal:AbortSignal.timeout(12000)});
   if(!shopResponse.ok)return send({ok:false,error:"Etsy shop ID auto lookup failed",status:shopResponse.status},502);
   const shopInfo=await shopResponse.json();
   actualShop=String(shopInfo.shop_id||"");
   if(!/^[0-9]+$/.test(actualShop))return send({ok:false,error:"Etsy shop ID not found"},502);
  }
  const endpoint="https://api.etsy.com/v3/application/shops/"+actualShop;
  const headers={"x-api-key":key,"authorization":"Bearer "+token};
  if(["upload_file","upload_image","listing_status"].includes(action)){
   const listing=String(body.listing_id||"");
   if(!/^[1-9][0-9]{0,17}$/.test(listing))return send({ok:false,error:"Invalid listing ID"},400);
   const path=endpoint+"/listings/"+listing;
   if(action==="listing_status"){
    const r=await fetch(path,{headers,signal:AbortSignal.timeout(12000)});
    const data=await r.json().catch(()=>({}));
    if(!r.ok)return send({ok:false,error:"Listing lookup failed",status:r.status},502);
    return send({ok:true,listing_id:listing,state:data.state||null,type:data.type||null,title:data.title||null});
   }
   if(body.confirmation!=="この非公開商品にファイルを登録する")return send({ok:false,error:"Explicit approval required"},403);
   const filename=String(body.filename||"");
   if(!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,110}$/.test(filename)||filename.includes(".."))return send({ok:false,error:"Invalid filename"},400);
   const encoded=String(body.data_base64||"");
   if(!encoded||encoded.length>11000000||!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded))return send({ok:false,error:"Invalid file or size limit (8 MB)"},400);
   const raw=Uint8Array.from(atob(encoded),ch=>ch.charCodeAt(0));
   if(raw.length>8*1024*1024)return send({ok:false,error:"File exceeds 8 MB"},413);
   const form=new FormData();
   const isImage=action==="upload_image";
   if(isImage&&!/\.(jpg|jpeg|png)$/i.test(filename))return send({ok:false,error:"Only JPEG or PNG listing images supported"},400);
   form.append(isImage?"image":"file",new Blob([raw]),filename);
   if(!isImage)form.append("name",filename);
   const upload=await fetch(path+(isImage?"/images":"/files"),{method:"POST",headers,body:form,signal:AbortSignal.timeout(25000)});
   const data=await upload.json().catch(()=>({}));
   if(!upload.ok)return send({ok:false,error:"Etsy upload failed",status:upload.status},502);
   return send({ok:true,listing_id:listing,uploaded:true,asset_id:isImage?data.listing_image_id:data.listing_file_id||null,published:false});
  }
  if(action==="orders"){
   const p=new URLSearchParams({limit:"100",offset:"0"});
   const r=await fetch(endpoint+"/receipts?"+p,{headers,signal:AbortSignal.timeout(15000)});
   if(!r.ok)return send({ok:false,error:"Etsy receipts query failed",status:r.status},502);
   const d=await r.json(),orders=Array.isArray(d.results)?d.results:[];
   return send({ok:true,receipt_count:orders.length,total_available:Number.isFinite(d.count)?d.count:null,paid_count:orders.filter((x:any)=>x.is_paid===true).length,canceled_count:orders.filter((x:any)=>x.was_canceled===true).length,has_more:!!(d.count&&d.count>orders.length),note:"Receipts are not equivalent to net profit; no amount or revenue is inferred."});
  }
  if(body.confirmation!=="Etsyに非公開の下書きを作成する")return send({error:"Explicit draft creation confirmation required"},403);
  const d=body.listing;
  if(!d||typeof d!=="object"||!String(d.title||"").trim()||!String(d.description||"").trim()||!Number.isInteger(d.quantity)||d.quantity<1||!Number.isFinite(d.price)||d.price<=0||!Number.isInteger(d.taxonomy_id)||d.taxonomy_id<=0||!["i_did","collective","someone_else"].includes(d.who_made)||!String(d.when_made||"").trim()||typeof d.is_digital!=="boolean")return send({error:"Invalid or incomplete listing; review taxonomies and required attributes"},400);
  const params=new URLSearchParams({title:String(d.title).trim(),description:String(d.description).trim(),quantity:String(d.quantity),price:String(d.price),taxonomy_id:String(d.taxonomy_id),who_made:String(d.who_made),when_made:String(d.when_made),type:d.is_digital?"download":"physical",is_supply:"false"});
  const response=await fetch(endpoint+"/listings",{method:"POST",headers:{...headers,"content-type":"application/x-www-form-urlencoded"},body:params,signal:AbortSignal.timeout(15000)});
  const result=await response.json().catch(()=>({}));
  if(!response.ok)return send({ok:false,error:"Etsy draft creation failed",status:response.status,details:result.error||result.error_message||null},502);
  return send({ok:true,draft_created:true,listing_id:result.listing_id||null,state:result.state||"draft",published:false,note:"Files/images and listing compliance must be confirmed separately before publication."});
 }catch(e){return send({ok:false,error:e instanceof Error?e.message:"Unexpected error"},500)}
});