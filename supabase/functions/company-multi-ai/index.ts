import {decodeProtectedHeader,importX509,jwtVerify} from "npm:jose@5.9.6";
const headers={"Access-Control-Allow-Origin":"https://kazuobi1234.github.io","Access-Control-Allow-Headers":"authorization,content-type","Access-Control-Allow-Methods":"POST,OPTIONS","Content-Type":"application/json"};
const reply=(data:unknown,status=200)=>new Response(JSON.stringify(data),{status,headers});
async function authorized(req:Request){
 const bearer=req.headers.get("authorization")||"";
 if(!bearer.startsWith("Bearer "))return false;
 const jwt=bearer.slice(7),{kid,alg}=decodeProtectedHeader(jwt);
 if(alg!=="RS256"||!kid)return false;
 const resp=await fetch("https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com",{signal:AbortSignal.timeout(10000)});
 if(!resp.ok)throw Error("Identity verification unavailable");
 const cert=(await resp.json())[kid];if(!cert)return false;
 const {payload}=await jwtVerify(jwt,await importX509(cert,"RS256"),{issuer:"https://securetoken.google.com/gensou-flow",audience:"gensou-flow"});
 return Boolean(Deno.env.get("ALLOWED_FIREBASE_UID")&&payload.sub===Deno.env.get("ALLOWED_FIREBASE_UID"));
}
Deno.serve(async(req:Request)=>{
 if(req.method==="OPTIONS")return new Response(null,{status:204,headers});
 if(req.method!=="POST")return reply({ok:false,error:"Method not allowed"},405);
 try{
  if(!await authorized(req))return reply({ok:false,error:"認証されていません"},401);
  const input=await req.json().catch(()=>({}));
  const provider=input.provider;
  if(!["claude","gemini"].includes(provider))return reply({ok:false,error:"AIの指定が正しくありません"},400);
  const k=provider==="claude"?"ANTHROPIC_API_KEY":"GEMINI_API_KEY";
  const modelKey=provider==="claude"?"ANTHROPIC_MODEL":"GEMINI_MODEL";
  const apiKey=Deno.env.get(k)||"",model=provider==="gemini"?"gemini-3.5-flash-lite":(Deno.env.get(modelKey)||"");
  if(input.action==="status")return reply({ok:true,provider,configured:Boolean(apiKey&&model),missing:provider==="gemini"?(apiKey?[]:[k]):[k,modelKey].filter(x=>!Deno.env.get(x)),model,free_only:true,usage_enabled:false,test_performed:false,note:"APIキーの有無のみ確認。無料枠と課金設定は未確認です。"});
  if(provider!=="gemini"||input.action!=="test")return reply({ok:false,error:"利用不可"},403);
  if(!apiKey)return reply({ok:false,error:"Gemini設定なし"},503);
  if(input.confirmation!=="無料枠接続テスト")return reply({ok:false,error:"確認が必要"},403);
  const response=await fetch("https://generativelanguage.googleapis.com/v1beta/models/"+model+":generateContent",{method:"POST",headers:{"x-goog-api-key":apiKey,"content-type":"application/json"},body:JSON.stringify({contents:[{parts:[{text:"日本語で接続成功と返答してください"}]}],generationConfig:{maxOutputTokens:60}}),signal:AbortSignal.timeout(15000)});
  if(!response.ok){const failure=await response.json().catch(()=>({}));const reason=String(failure.error?.status||"UNKNOWN");console.error("Gemini upstream failure",JSON.stringify({status:response.status,reason}));return reply({ok:false,error:"Gemini通信エラー：HTTP "+response.status+" / "+reason,upstream_status:response.status,reason,message:String(failure.error?.message||"詳細なし").slice(0,350)},502);}
  const data=await response.json();
  return reply({ok:true,answer:(data.candidates||[]).flatMap((x:any)=>x.content?.parts||[]).map((x:any)=>x.text||"").join(""),model});

 }catch(e){return reply({ok:false,error:e instanceof Error?e.message:"サーバーエラー"},500)}
});