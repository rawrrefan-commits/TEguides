const SESSION_COOKIE = "te_secure_session";
const SESSION_MAX_AGE = 24 * 60 * 60;
const FIRESTORE_SCOPE = "https://www.googleapis.com/auth/datastore";
const TOKEN_URL = "https://oauth2.googleapis.com/token";
const FIRESTORE_BASE = "https://firestore.googleapis.com/v1";

let cachedGoogleToken = null;
let cachedGoogleTokenExp = 0;
let cachedSessionKey = null;

function json(data, status=200, extra={}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type":"application/json; charset=utf-8", "Cache-Control":"no-store", ...extra }
  });
}
function b64url(bytes) {
  let s = "";
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i=0;i<arr.length;i+=0x8000) s += String.fromCharCode(...arr.subarray(i,i+0x8000));
  return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
}
function unb64url(s) {
  s=s.replace(/-/g,"+").replace(/_/g,"/");
  while(s.length%4)s+="=";
  const raw=atob(s); const out=new Uint8Array(raw.length);
  for(let i=0;i<raw.length;i++)out[i]=raw.charCodeAt(i);
  return out;
}
function utf8(s){return new TextEncoder().encode(s)}
function parseCookies(request){
  const out={};
  const raw=request.headers.get("Cookie")||"";
  for(const part of raw.split(";")){
    const i=part.indexOf("="); if(i<0)continue;
    out[part.slice(0,i).trim()]=part.slice(i+1).trim();
  }
  return out;
}
function cookieHeader(value,maxAge=SESSION_MAX_AGE){
  return `${SESSION_COOKIE}=${value}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Strict`;
}
function clearCookie(){return `${SESSION_COOKIE}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict`}

async function getSessionCryptoKey(env){
  if(cachedSessionKey)return cachedSessionKey;
  if(!env.SESSION_SECRET || env.SESSION_SECRET.length<32) throw new Error("SESSION_SECRET belum dikonfigurasi.");
  const digest=await crypto.subtle.digest("SHA-256",utf8(env.SESSION_SECRET));
  cachedSessionKey=await crypto.subtle.importKey("raw",digest,{name:"AES-GCM"},false,["encrypt","decrypt"]);
  return cachedSessionKey;
}
async function encryptSession(payload,env){
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const key=await getSessionCryptoKey(env);
  const data=utf8(JSON.stringify(payload));
  const ct=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,data);
  return `${b64url(iv)}.${b64url(ct)}`;
}
async function decryptSession(token,env){
  try{
    const [a,b]=String(token||"").split("."); if(!a||!b)return null;
    const key=await getSessionCryptoKey(env);
    const pt=await crypto.subtle.decrypt({name:"AES-GCM",iv:unb64url(a)},key,unb64url(b));
    const data=JSON.parse(new TextDecoder().decode(pt));
    if(!data || !data.key || !data.deviceId || !data.iat || data.exp < Math.floor(Date.now()/1000))return null;
    return data;
  }catch{return null;}
}

function pemToArrayBuffer(pem){
  const b64=pem.replace(/-----BEGIN PRIVATE KEY-----/g,"").replace(/-----END PRIVATE KEY-----/g,"").replace(/\\n/g,"").replace(/\s+/g,"");
  return unb64url(b64.replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,""));
}
async function googleAccessToken(env){
  const now=Math.floor(Date.now()/1000);
  if(cachedGoogleToken && cachedGoogleTokenExp-now>120)return cachedGoogleToken;
  const email=env.FIREBASE_CLIENT_EMAIL;
  const privateKey=(env.FIREBASE_PRIVATE_KEY||"").replace(/\\n/g,"\n");
  if(!email||!privateKey)throw new Error("Firebase service account secret belum dikonfigurasi.");
  const header={alg:"RS256",typ:"JWT"};
  const claim={iss:email,scope:FIRESTORE_SCOPE,aud:TOKEN_URL,iat:now,exp:now+3600};
  const enc=o=>b64url(utf8(JSON.stringify(o)));
  const unsigned=`${enc(header)}.${enc(claim)}`;
  const key=await crypto.subtle.importKey("pkcs8",pemToArrayBuffer(privateKey),{name:"RSASSA-PKCS1-v1_5",hash:"SHA-256"},false,["sign"]);
  const sig=await crypto.subtle.sign({name:"RSASSA-PKCS1-v1_5"},key,utf8(unsigned));
  const assertion=`${unsigned}.${b64url(sig)}`;
  const r=await fetch(TOKEN_URL,{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:new URLSearchParams({grant_type:"urn:ietf:params:oauth:grant-type:jwt-bearer",assertion})});
  const d=await r.json();
  if(!r.ok||!d.access_token)throw new Error(`Google token gagal (${r.status}).`);
  cachedGoogleToken=d.access_token; cachedGoogleTokenExp=now+Number(d.expires_in||3600);
  return cachedGoogleToken;
}
function fsValue(fields,name){
  const f=fields?.[name]; if(!f)return undefined;
  if("stringValue" in f)return f.stringValue;
  if("booleanValue" in f)return f.booleanValue;
  if("timestampValue" in f)return Date.parse(f.timestampValue);
  if("integerValue" in f)return Number(f.integerValue);
  if("doubleValue" in f)return Number(f.doubleValue);
  return undefined;
}
function fsFields(obj){
  const out={};
  for(const [k,v] of Object.entries(obj||{})){
    if(typeof v==="boolean")out[k]={booleanValue:v};
    else if(typeof v==="string")out[k]={stringValue:v};
    else if(typeof v==="number")out[k]={integerValue:String(v)};
  }
  return out;
}
async function firestoreDoc(env,key){
  const token=await googleAccessToken(env);
  const url=`${FIRESTORE_BASE}/projects/${encodeURIComponent(env.FIREBASE_PROJECT_ID)}/databases/(default)/documents/keys/${encodeURIComponent(key)}`;
  const r=await fetch(url,{headers:{Authorization:`Bearer ${token}`}});
  if(r.status===404)return null;
  if(!r.ok)throw new Error(`Firestore GET gagal (${r.status}).`);
  return r.json();
}
async function bindDevice(env,key,deviceId,updateTime){
  const token=await googleAccessToken(env);
  const base=`${FIRESTORE_BASE}/projects/${encodeURIComponent(env.FIREBASE_PROJECT_ID)}/databases/(default)/documents/keys/${encodeURIComponent(key)}`;
  const url=`${base}?updateMask.fieldPaths=deviceId&currentDocument.updateTime=${encodeURIComponent(updateTime)}`;
  const r=await fetch(url,{method:"PATCH",headers:{Authorization:`Bearer ${token}`,"Content-Type":"application/json"},body:JSON.stringify({fields:{deviceId:{stringValue:deviceId}}})});
  if(r.ok)return true;
  return false;
}
async function validateKey(env,key,deviceId,bind=true){
  key=String(key||"").trim(); deviceId=String(deviceId||"").trim();
  if(!key)return {ok:false,status:400,message:"Key tidak boleh kosong."};
  if(!deviceId)return {ok:false,status:400,message:"Device ID tidak valid."};
  const doc=await firestoreDoc(env,key);
  if(!doc)return {ok:false,status:401,message:"Key tidak ditemukan / salah."};
  const fields=doc.fields||{};
  const aktif=fsValue(fields,"aktif");
  const expiredAtMs=fsValue(fields,"expired");
  const savedDevice=fsValue(fields,"deviceId");
  if(aktif===false)return {ok:false,status:403,message:"Key ini sudah dinonaktifkan."};
  if(expiredAtMs && expiredAtMs < Date.now())return {ok:false,status:403,message:"Key sudah kedaluwarsa (expired)."};
  if(savedDevice){
    if(savedDevice!==deviceId)return {ok:false,status:403,message:"Key ini sudah digunakan di perangkat lain."};
  }else if(bind){
    const ok=await bindDevice(env,key,deviceId,doc.updateTime);
    if(!ok){
      const again=await firestoreDoc(env,key);
      const d=fsValue(again?.fields,"deviceId");
      if(d!==deviceId)return {ok:false,status:403,message:"Key ini sudah digunakan di perangkat lain."};
    }
  }
  return {ok:true,key,deviceId,expiredAtMs:expiredAtMs||null};
}
async function requireSession(request,env){
  const token=parseCookies(request)[SESSION_COOKIE];
  const session=await decryptSession(token,env);
  if(!session)return {ok:false,response:json({ok:false,message:"Sesi tidak valid."},401,{"Set-Cookie":clearCookie()})};
  const state=await validateKey(env,session.key,session.deviceId,false);
  if(!state.ok)return {ok:false,response:json({ok:false,message:state.message},401,{"Set-Cookie":clearCookie()})};
  return {ok:true,session,state};
}
function calculate(payload){
  const ovr=Number(payload?.ovr), formula=Number(payload?.formula);
  const attrs=Array.isArray(payload?.attributes)?payload.attributes:[];
  const allowed=new Set([80,90,100,110,120,130,140,150,160,170,180]);
  if(!Number.isFinite(ovr)||ovr<0||ovr>999)throw new Error("OVR tidak valid.");
  if(!allowed.has(formula))throw new Error("Formula tidak valid.");
  if(attrs.length>50)throw new Error("Jumlah atribut terlalu banyak.");
  let total=0,count=0;
  for(const item of attrs){const raw=String(item?.value??"").trim();if(!raw)continue;const v=Number.parseFloat(raw);if(!Number.isFinite(v))continue;if(v<0||v>9999)throw new Error("Nilai atribut tidak valid.");total+=v;count++;}
  const maksimal=count*formula, selisih=maksimal-total, peningkatan=selisih/15, rataRata=count?selisih/count:0, finalOVR=ovr+Math.round(peningkatan);
  const fmt=n=>Number.isInteger(n)?String(n):Number(n).toFixed(5).replace(/0+$/,'').replace(/\.$/,'');
  return {totalAtribut:total,maksimal,peningkatan:fmt(peningkatan),rataRata:fmt(rataRata),finalOVR};
}
async function serveApp(request,env){
  const auth=await requireSession(request,env); if(!auth.ok)return auth.response;
  const assetRequest=new Request(new URL("/calculator.html",request.url),request);
  const res=await env.ASSETS.fetch(assetRequest);
  const h=new Headers(res.headers); h.set("Cache-Control","no-store, no-cache, must-revalidate, private"); h.set("X-Content-Type-Options","nosniff"); h.set("Content-Security-Policy","default-src 'self' https://cdn.jsdelivr.net; script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
  return new Response(res.body,{status:res.status,headers:h});
}

export default {
  async fetch(request,env){
    const url=new URL(request.url);
    try{
      if(url.pathname==="/api/login" && request.method==="POST"){
        const body=await request.json().catch(()=>({}));
        const result=await validateKey(env,body.key,body.deviceId,true);
        if(!result.ok)return json({ok:false,message:result.message},result.status);
        const now=Math.floor(Date.now()/1000);
        const token=await encryptSession({key:result.key,deviceId:result.deviceId,iat:now,exp:now+SESSION_MAX_AGE},env);
        return json({ok:true,expiredAtMs:result.expiredAtMs,serverNowMs:Date.now()},200,{"Set-Cookie":cookieHeader(token)});
      }
      if(url.pathname==="/api/session" && request.method==="GET"){
        const auth=await requireSession(request,env); if(!auth.ok)return auth.response;
        return json({ok:true,expiredAtMs:auth.state.expiredAtMs,serverNowMs:Date.now()});
      }
      if(url.pathname==="/api/logout" && request.method==="POST")return json({ok:true},200,{"Set-Cookie":clearCookie()});
      if(url.pathname==="/api/calculate" && request.method==="POST"){
        const auth=await requireSession(request,env); if(!auth.ok)return auth.response;
        const body=await request.json().catch(()=>({}));
        try{return json({ok:true,...calculate(body)});}catch(e){return json({ok:false,message:e.message||"Perhitungan gagal."},400);}
      }
      if(url.pathname==="/app" || url.pathname==="/app/")return serveApp(request,env);
      if(url.pathname==="/calculator.html" || url.pathname==="/assets/calculator.html"){
        const auth=await requireSession(request,env); if(!auth.ok)return auth.response;
        return serveApp(request,env);
      }
      // Jangan biarkan asset kalkulator dibypass lewat path asset langsung.
      if(url.pathname.startsWith("/private/") || url.pathname==="/assets/calculator.html")return new Response("Not Found",{status:404});
      return env.ASSETS.fetch(request);
    }catch(e){
      console.error(e);
      return json({ok:false,message:"Server mengalami error. Cek konfigurasi Cloudflare/Firebase."},500);
    }
  }
};
