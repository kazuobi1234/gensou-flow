import { decodeProtectedHeader, importX509, jwtVerify } from "npm:jose@5.9.6";
const cors={"Access-Control-Allow-Origin":"https://kazuobi1234.github.io","Access-Control-Allow-Headers":"authorization,content-type","Access-Control-Allow-Methods":"POST,OPTIONS","Content-Type":"application/json"};
const reply=(d:unknown,s=200)=>new Response(JSON.stringify(d),{status:s,headers:cors});
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


Deno.serve(async(req:Request)=>{
 if(req.method==="OPTIONS")return new Response(null,{status:204,headers:cors});
 if(req.method!=="POST")return reply({ok:false,error:"Method not allowed"},405);
 try{
  if(!await verifyOwner(req))return reply({ok:false,error:"Unauthorized"},401);
  const token=Deno.env.get("INSTAGRAM_ACCESS_TOKEN"),id=Deno.env.get("INSTAGRAM_USER_ID");
  if(!token||!id)return reply({ok:false,configured:false,token_valid:false,error:"Instagram server secrets missing"},200);
  const url=new URL("https://graph.instagram.com/v26.0/me");
  url.searchParams.set("fields","id,username,account_type");
  const res=await fetch(url,{method:"GET",headers:{Authorization:"Bearer "+token},signal:AbortSignal.timeout(10000)});
  const data=await res.json().catch(()=>({}));
  if(!res.ok)return reply({ok:true,configured:true,token_valid:false,meta_http_status:res.status,meta_error_code:typeof data.error?.code==="number"?data.error.code:null,publish_permission:"not_checked",published:false});
  const secondUrl=new URL("https://graph.instagram.com/v26.0/me");
  secondUrl.searchParams.set("fields","user_id");
  let scopedUserId=null;
  try{
   const r=await fetch(secondUrl,{headers:{Authorization:"Bearer "+token},signal:AbortSignal.timeout(10000)});
   if(r.ok){const parsed=await r.json();if(parsed.user_id!=null)scopedUserId=String(parsed.user_id)}
  }catch(_){}
  // Read-only permission probe. If this endpoint is unavailable, report unverified; never infer authorization.
  let permissionState="not_verified";
  let permissionHttpStatus: number|null=null;
  let permissionErrorCode: number|null=null;
  let permissionErrorSubcode: number|null=null;
  let permissionErrorType: string|null=null;
  try{
   const p=await fetch("https://graph.instagram.com/v26.0/me/permissions",{
     method:"GET",headers:{Authorization:"Bearer "+token},signal:AbortSignal.timeout(10000)
   });
   permissionHttpStatus=p.status;
   const result=await p.json().catch(()=>({}));
   if(p.ok&&Array.isArray(result.data)){
     const match=result.data.find((x:unknown)=>{
       const v=x as {permission?:string};
       return v.permission==="instagram_business_content_publish";
     });
     if(match)permissionState=(match.status==="granted"?"granted":"not_granted");
     else permissionState="not_listed";
   }else{
     permissionErrorCode=typeof result.error?.code==="number"?result.error.code:null;
     permissionErrorSubcode=typeof result.error?.error_subcode==="number"?result.error.error_subcode:null;
     permissionErrorType=typeof result.error?.type==="string"?result.error.type:null;
   }
  }catch(_){ permissionState="not_verified"; }
    return reply({ok:true,configured:true,token_valid:true,account_matches:String(data.id)===String(id),id_field_matches:String(data.id)===String(id),user_id_field_matches:scopedUserId===null?null:scopedUserId===String(id),user_id_available:scopedUserId!==null,username:typeof data.username==="string"?data.username:null,username_matches_expected:typeof data.username==="string"?data.username.toLowerCase()==="kunogistudio":null,account_type:typeof data.account_type==="string"?data.account_type:null,publish_permission:permissionState,publish_permission_http_status:permissionHttpStatus,publish_error_code:permissionErrorCode,publish_error_subcode:permissionErrorSubcode,publish_error_type:permissionErrorType,published:false});
 }catch(e){return reply({ok:false,error:"Metadata check failed",published:false},502)}
});