const SESSION_COOKIE = "te_secure_session";
const SESSION_MAX_AGE = 24 * 60 * 60;
const FIRESTORE_SCOPE = "https://www.googleapis.com/auth/datastore";
const TOKEN_URL = "https://oauth2.googleapis.com/token";
const FIRESTORE_BASE = "https://firestore.googleapis.com/v1";

let cachedGoogleToken = null;
let cachedGoogleTokenExp = 0;
let cachedSessionKey = null;

function json(data, status=200, extra={}) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type":"application/json; charset=utf-8", "Cache-Control":"no-store", ...extra } });
}
function b64url(bytes) { const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes); let s=""; for(let i=0;i<arr.length;i+=0x8000)s+=String.fromCharCode(...arr.subarray(i,i+0x8000)); return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,""); }
function unb64url(s) { s=String(s).replace(/-/g,"+").replace(/_/g,"/"); while(s.length%4)s+="="; const raw=atob(s),out=new Uint8Array(raw.length); for(let i=0;i<raw.length;i++)out[i]=raw.charCodeAt(i); return out; }
function utf8(s){return new TextEncoder().encode(s)}
function parseCookies(request){const out={};for(const part of (request.headers.get("Cookie")||"").split(";")){const i=part.indexOf("=");if(i>=0)out[part.slice(0,i).trim()]=part.slice(i+1).trim()}return out}
function cookieHeader(value,maxAge=SESSION_MAX_AGE){return `${SESSION_COOKIE}=${value}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Strict`}
function clearCookie(){return `${SESSION_COOKIE}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict`}

async function getSessionCryptoKey(env){
  if(cachedSessionKey)return cachedSessionKey;
  if(!env.SESSION_SECRET || env.SESSION_SECRET.length<32)throw new Error("SESSION_SECRET belum dikonfigurasi.");
  const digest=await crypto.subtle.digest("SHA-256",utf8(env.SESSION_SECRET));
  cachedSessionKey=await crypto.subtle.importKey("raw",digest,{name:"AES-GCM"},false,["encrypt","decrypt"]);
  return cachedSessionKey;
}
async function encryptSession(payload,env){const iv=crypto.getRandomValues(new Uint8Array(12));const key=await getSessionCryptoKey(env);const ct=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,utf8(JSON.stringify(payload)));return `${b64url(iv)}.${b64url(ct)}`}
async function decryptSession(token,env){try{const [a,b]=String(token||"").split(".");if(!a||!b)return null;const key=await getSessionCryptoKey(env);const pt=await crypto.subtle.decrypt({name:"AES-GCM",iv:unb64url(a)},key,unb64url(b));const d=JSON.parse(new TextDecoder().decode(pt));if(!d?.key||!d?.deviceId||!d?.iat||d.exp<Math.floor(Date.now()/1000))return null;return d}catch{return null}}
function pemToArrayBuffer(pem){const b64=String(pem).replace(/-----BEGIN PRIVATE KEY-----/g,"").replace(/-----END PRIVATE KEY-----/g,"").replace(/\\n/g,"").replace(/\s+/g,"");const bin=atob(b64);const out=new Uint8Array(bin.length);for(let i=0;i<bin.length;i++)out[i]=bin.charCodeAt(i);return out.buffer}
async function googleAccessToken(env){
  const now=Math.floor(Date.now()/1000);
  if(cachedGoogleToken&&cachedGoogleTokenExp-now>120)return cachedGoogleToken;
  const email=env.FIREBASE_CLIENT_EMAIL, privateKey=String(env.FIREBASE_PRIVATE_KEY||"").replace(/\\n/g,"\n");
  if(!email||!privateKey)throw new Error("Firebase service account secret belum dikonfigurasi.");
  const enc=o=>b64url(utf8(JSON.stringify(o))), header={alg:"RS256",typ:"JWT"}, claim={iss:email,scope:FIRESTORE_SCOPE,aud:TOKEN_URL,iat:now,exp:now+3600}, unsigned=`${enc(header)}.${enc(claim)}`;
  const key=await crypto.subtle.importKey("pkcs8",pemToArrayBuffer(privateKey),{name:"RSASSA-PKCS1-v1_5",hash:"SHA-256"},false,["sign"]);
  const sig=await crypto.subtle.sign({name:"RSASSA-PKCS1-v1_5"},key,utf8(unsigned));
  const assertion=`${unsigned}.${b64url(sig)}`;
  const r=await fetch(TOKEN_URL,{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:new URLSearchParams({grant_type:"urn:ietf:params:oauth:grant-type:jwt-bearer",assertion})});
  const d=await r.json().catch(()=>({})); if(!r.ok||!d.access_token)throw new Error(`Google token gagal (${r.status}).`); cachedGoogleToken=d.access_token;cachedGoogleTokenExp=now+Number(d.expires_in||3600);return d.access_token;
}
function fsValue(fields,name){const f=fields?.[name];if(!f)return undefined;if("stringValue"in f)return f.stringValue;if("booleanValue"in f)return f.booleanValue;if("timestampValue"in f)return Date.parse(f.timestampValue);if("integerValue"in f)return Number(f.integerValue);if("doubleValue"in f)return Number(f.doubleValue);return undefined}
async function firestoreDoc(env,key){const token=await googleAccessToken(env);const url=`${FIRESTORE_BASE}/projects/${encodeURIComponent(env.FIREBASE_PROJECT_ID)}/databases/(default)/documents/keys/${encodeURIComponent(key)}`;const r=await fetch(url,{headers:{Authorization:`Bearer ${token}`}});if(r.status===404)return null;if(!r.ok)throw new Error(`Firestore GET gagal (${r.status}).`);return r.json()}
async function bindDevice(env,key,deviceId,updateTime){const token=await googleAccessToken(env);const base=`${FIRESTORE_BASE}/projects/${encodeURIComponent(env.FIREBASE_PROJECT_ID)}/databases/(default)/documents/keys/${encodeURIComponent(key)}`;const url=`${base}?updateMask.fieldPaths=deviceId&currentDocument.updateTime=${encodeURIComponent(updateTime)}`;const r=await fetch(url,{method:"PATCH",headers:{Authorization:`Bearer ${token}`,"Content-Type":"application/json"},body:JSON.stringify({fields:{deviceId:{stringValue:deviceId}}})});return r.ok}
async function validateKey(env,key,deviceId,bind=true){
  key=String(key||"").trim();deviceId=String(deviceId||"").trim();if(!key)return{ok:false,status:400,message:"Key tidak boleh kosong."};if(!deviceId)return{ok:false,status:400,message:"Device ID tidak valid."};
  const doc=await firestoreDoc(env,key);if(!doc)return{ok:false,status:401,message:"Key tidak ditemukan / salah."};
  const f=doc.fields||{},aktif=fsValue(f,"aktif"),expired=fsValue(f,"expired"),saved=fsValue(f,"deviceId");
  if(aktif===false)return{ok:false,status:403,message:"Key ini sudah dinonaktifkan."};if(expired&&expired<Date.now())return{ok:false,status:403,message:"Key sudah kedaluwarsa (expired)."};
  if(saved){if(saved!==deviceId)return{ok:false,status:403,message:"Key ini sudah digunakan di perangkat lain."};}
  else if(bind){const ok=await bindDevice(env,key,deviceId,doc.updateTime);if(!ok){const again=await firestoreDoc(env,key);const d=fsValue(again?.fields,"deviceId");if(d!==deviceId)return{ok:false,status:403,message:"Key ini sudah digunakan di perangkat lain."};}}
  return{ok:true,key,deviceId,expiredAtMs:expired||null};
}
async function requireSession(request,env){const session=await decryptSession(parseCookies(request)[SESSION_COOKIE],env);if(!session)return{ok:false,response:json({ok:false,message:"Sesi tidak valid."},401,{"Set-Cookie":clearCookie()})};const state=await validateKey(env,session.key,session.deviceId,false);if(!state.ok)return{ok:false,response:json({ok:false,message:state.message},401,{"Set-Cookie":clearCookie()})};return{ok:true,session,state}}
function calculate(payload){const ovr=Number(payload?.ovr),formula=Number(payload?.formula),attrs=Array.isArray(payload?.attributes)?payload.attributes:[],allowed=new Set([80,90,100,110,120,130,140,150,160,170,180]);if(!Number.isFinite(ovr)||ovr<0||ovr>999)throw new Error("OVR tidak valid.");if(!allowed.has(formula))throw new Error("Formula tidak valid.");if(attrs.length>50)throw new Error("Jumlah atribut terlalu banyak.");let total=0,count=0;for(const item of attrs){const raw=String(item?.value??"").trim();if(!raw)continue;const v=Number.parseFloat(raw);if(!Number.isFinite(v))continue;if(v<0||v>9999)throw new Error("Nilai atribut tidak valid.");total+=v;count++}const maksimal=count*formula,selisih=maksimal-total,peningkatan=selisih/15,rataRata=count?selisih/count:0,finalOVR=ovr+Math.round(peningkatan);const fmt=n=>Number.isInteger(n)?String(n):Number(n).toFixed(5).replace(/0+$/,'').replace(/\.$/,'');return{totalAtribut:total,maksimal,peningkatan:fmt(peningkatan),rataRata:fmt(rataRata),finalOVR}}

async function protectedAsset(context){const auth=await requireSession(context.request,context.env);if(!auth.ok)return auth.response;const res=await context.env.ASSETS.fetch(new Request(new URL("/calculator.html",context.request.url),context.request));const h=new Headers(res.headers);h.set("Cache-Control","no-store, no-cache, must-revalidate, private");h.set("X-Content-Type-Options","nosniff");h.set("Content-Security-Policy","default-src 'self' https://cdn.jsdelivr.net; script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");return new Response(res.body,{status:res.status,headers:h})}

export async function onRequest(context){
  const {request,env}=context,url=new URL(request.url);
  try{
    if(url.pathname==="/api/login"&&request.method==="POST"){const body=await request.json().catch(()=>({}));const r=await validateKey(env,body.key,body.deviceId,true);if(!r.ok)return json({ok:false,message:r.message},r.status);const now=Math.floor(Date.now()/1000),token=await encryptSession({key:r.key,deviceId:r.deviceId,iat:now,exp:now+SESSION_MAX_AGE},env);return json({ok:true,expiredAtMs:r.expiredAtMs,serverNowMs:Date.now()},200,{"Set-Cookie":cookieHeader(token)})}
    if(url.pathname==="/api/session"&&request.method==="GET"){const a=await requireSession(request,env);if(!a.ok)return a.response;return json({ok:true,expiredAtMs:a.state.expiredAtMs,serverNowMs:Date.now()})}
    if(url.pathname==="/api/logout"&&request.method==="POST")return json({ok:true},200,{"Set-Cookie":clearCookie()});
    if(url.pathname==="/api/calculate"&&request.method==="POST"){const a=await requireSession(request,env);if(!a.ok)return a.response;const body=await request.json().catch(()=>({}));try{return json({ok:true,...calculate(body)})}catch(e){return json({ok:false,message:e.message||"Perhitungan gagal."},400)}}
    if(url.pathname==="/app"||url.pathname==="/app/"||url.pathname==="/calculator.html"||url.pathname==="/assets/calculator.html"||url.pathname.startsWith("/private/"))return protectedAsset(context);
    return context.next();
  }catch(e){console.error(e);return json({ok:false,message:"Server mengalami error. Cek konfigurasi Cloudflare/Firebase."},500)}
}
