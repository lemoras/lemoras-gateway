// ---------------------------
// Config
// ---------------------------
const cookieSuffix = "_token";
const accountTokenCookie = "account_token";
const tokenLength = 32;
const tokenExpirySeconds = 20 * 60;
const tokenExtendSeconds = 15 * 60;
const tokenRenewThreshSeconds = 10 * 60;
const normalRateLimit = 50;
const validationRateLimit = 350;
const rateLimitWindowSeconds = 60;
let allowedOrigins = [
  'https://lemoras.com',
  'https://account.lemoras.com',
  'https://notes.lemoras.com',
  'https://drive.lemoras.com',
  'https://passwords.lemoras.com',
  'https://planner.lemoras.com',
  'https://worker.lemoras.com'
];
const refreshRateLimitPerDay = 3;

const trustedURLs = [
  { url: "https://worker.lemoras.com/security/validation", limit: 250 },
];

// ---------------------------
// Crypto Key Caching
// ---------------------------
let HMAC_KEY;
async function initKeys(env) {
  if (!HMAC_KEY) {
    const enc = new TextEncoder();
    HMAC_KEY = await crypto.subtle.importKey(
      'raw', enc.encode(env.RATE_SECRET_KEY),
      { name:'HMAC', hash:'SHA-256' },
      false,
      ['sign','verify']
    );
  }
}

// ---------------------------
// Token Utilities (HMAC-only)
// ---------------------------
async function hmacSha256(data) {
  const enc = new TextEncoder();
  const sig = await crypto.subtle.sign('HMAC', HMAC_KEY, enc.encode(data));
  return new Uint8Array(sig);
}

function hexEncode(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2,'0')).join('');
}

async function generateSecureToken(token, env) {
  await initKeys(env);
  const ts = String(Date.now());
  const data = `${token}|${ts}`;
  const sigHex = hexEncode(await hmacSha256(data));
  return `${data}|${sigHex}`;
}

async function validateToken(encoded, env) {
  await initKeys(env);
  const parts = encoded.split('|');
  if (parts.length !== 3) throw new Error('invalid token format');
  const [token, tsStr, signatureHex] = parts;
  const expectedHex = hexEncode(await hmacSha256(`${token}|${tsStr}`));

  let diff = 0;
  for (let i=0;i<expectedHex.length;i++) diff |= expectedHex.charCodeAt(i) ^ signatureHex.charCodeAt(i);
  if (diff!==0) throw new Error('invalid token signature');

  const ageMs = Date.now() - Number(tsStr);
  if (ageMs > tokenExpirySeconds*1000) throw new Error('token expired');
  return { token, remainingMs: tokenExpirySeconds*1000 - ageMs };
}

// ---------------------------
// Helper Utilities
// ---------------------------
function getSubdomain(host, mainDomain) {
  host = host.toLowerCase();
  mainDomain = mainDomain.toLowerCase();
  if (host.startsWith('http://')) host = host.slice(7);
  if (host.startsWith('https://')) host = host.slice(8);
  if (!host.endsWith(mainDomain)) return '';
  let trimmed = host.slice(0, host.length - mainDomain.length);
  if (trimmed.endsWith('.')) trimmed = trimmed.slice(0,-1);
  return trimmed || '';
}

function makeSetCookieHeader(name, value, domain, maxAgeSeconds) {
  if (maxAgeSeconds < 0) {
    return `${name}=; Path=/; Domain=${domain.startsWith('.')?domain:`.${domain}`}; HttpOnly; Secure; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT`;
  }
  return `${name}=${value}; Path=/; Domain=${domain.startsWith('.')?domain:`.${domain}`}; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSeconds}`;
}

function parseCookies(cookieHeader) {
  const cookies = {};
  cookieHeader.split(';').forEach(c=>{
    const [k,v] = c.trim().split('=');
    if (k) cookies[k] = v || '';
  });
  return cookies;
}

// ---------------------------
// KV Fixed Window Rate Limiting
// ---------------------------
async function allowRequestKV(env, key, limit, windowSeconds = 60) {
  const now = Math.floor(Date.now()/1000);
  const windowKey = `${key}:${Math.floor(now/windowSeconds)}`;
  const countStr = await env.RATE_LIMIT_KV.get(windowKey);
  let count = countStr ? parseInt(countStr) : 0;
  if (count >= limit) return false;
  await env.RATE_LIMIT_KV.put(windowKey, String(count+1), { expirationTtl: windowSeconds*2 });
  return true;
}

// ---------------------------
// Cached Wrappers
// ---------------------------
const tokenCache = new Map();
const rateLimitCache = new Map();

async function cachedValidateToken(encoded, env, ttlMs = 30000) {
  const now = Date.now();
  const cached = tokenCache.get(encoded);
  if (cached && cached.expiry > now) return cached.result;
  const result = await validateToken(encoded, env);
  tokenCache.set(encoded, { result, expiry: now + ttlMs });
  return result;
}

async function cachedAllowRequestKV(env, key, limit, windowSeconds = 60, ttlMs = 5000) {
  const now = Date.now();
  const cacheKey = `${key}:${limit}:${windowSeconds}`;
  const cached = rateLimitCache.get(cacheKey);
  if (cached && cached.expiry > now) return cached.allowed;
  const allowed = await allowRequestKV(env, key, limit, windowSeconds);
  rateLimitCache.set(cacheKey, { allowed, expiry: now + ttlMs });
  return allowed;
}

// ---------------------------
// CORS Handling
// ---------------------------
function withCORS(resp, origin) {
  const newHeaders = new Headers(resp.headers);
  newHeaders.set('Access-Control-Allow-Origin', origin);
  newHeaders.set('Access-Control-Allow-Credentials', 'true');
  newHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  newHeaders.set('Access-Control-Allow-Headers', 'Authorization, Content-Type, X-CSRF-Token');
  newHeaders.set('Vary', 'Origin');
  return new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers: newHeaders });
}

function validateCORS(request) {
  const origin = request.headers.get('Origin');
  if (!origin) return null;
  try {
    const url = new URL(origin);
    if (allowedOrigins.includes(url.origin)) return url.origin;
  } catch (e) { return null; }
  return null;
}

// ---------------------------
// Logout Handler
// ---------------------------
async function handleLogout(request, env) {
  const origin = request.headers.get('Origin');
  const headers = new Headers();
  if (origin) {
    headers.set('Access-Control-Allow-Origin', origin);
    headers.set('Access-Control-Allow-Credentials', 'true');
    headers.set('Access-Control-Allow-Headers', 'Authorization, Content-Type, X-CSRF-Token');
    headers.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
  }

  if (request.method === 'OPTIONS') return new Response(null, { status: 200, headers });
  if (request.method !== 'POST') return new Response(JSON.stringify({ status: false, message: 'Method not allowed' }), { status: 405, headers });

  const cookieHeader = request.headers.get('cookie') || '';
  const cookies = parseCookies(cookieHeader);
  for (const name of Object.keys(cookies)) {
    if (name.endsWith(cookieSuffix)) {
      headers.append('Set-Cookie', makeSetCookieHeader(name, '', '.' + env.MAIN_DOMAIN, -1));
    }
  }

  headers.set('Content-Type', 'application/json');
  return new Response(JSON.stringify({ status: true, message: 'Logout operation is successful' }), { status: 200, headers });
}

// ---------------------------
// Proxy Handler
// ---------------------------
async function handleProxy(request, targetBase, env) {
  const url = new URL(request.url);
  const targetURL = targetBase + url.pathname + url.search;
  const reqHeaders = new Headers(request.headers);
  reqHeaders.delete('Authorization');

  const cookieHeader = request.headers.get('cookie') || '';
  const cookies = parseCookies(cookieHeader);
  const origin = request.headers.get('Origin') || '';
  const subdomain = getSubdomain(origin ? new URL(origin).host : url.host, env.MAIN_DOMAIN);
  
  let cookieName = subdomain ? subdomain + cookieSuffix : accountTokenCookie;
  let wrappedToken = cookies[cookieName];

  if (!wrappedToken && cookieName !== accountTokenCookie) {
    cookieName = accountTokenCookie;
    wrappedToken = cookies[cookieName];
  }

  if (wrappedToken) {
    try {
      const validated = await validateToken(wrappedToken, env);
      reqHeaders.set('Authorization', `Bearer ${validated.token}`);
    } catch(e) {}
  }


  const reqInit = {
    method: request.method,
    headers: reqHeaders,
    redirect: 'manual',
    body: request.method === 'GET' || request.method === 'HEAD' ? undefined : request.body,
  };
  return fetch(targetURL, reqInit);
}

// ---------------------------
// Token Renewal Handler
// ---------------------------
async function handleTokenRenewal(request, env, resp) {
  try {
    const cookieHeader = request.headers.get('cookie') || '';
    const cookies = parseCookies(cookieHeader);
    const origin = request.headers.get('Origin') || '';
    const subdomain = getSubdomain(origin ? new URL(origin).host : new URL(request.url).host, env.MAIN_DOMAIN);
    const cookieName = subdomain ? subdomain + cookieSuffix : accountTokenCookie;
    const wrapped = cookies[cookieName];
    if (!wrapped) return resp;

    const result = await cachedValidateToken(wrapped, env);
    if (result.remainingMs < tokenRenewThreshSeconds * 1000) {
      const setCookie = makeSetCookieHeader(cookieName, wrapped, '.' + env.MAIN_DOMAIN, tokenExtendSeconds);
      const newHeaders = new Headers(resp.headers);
      newHeaders.append('Set-Cookie', setCookie);
      resp = new Response(await resp.clone().arrayBuffer(), { status: resp.status, statusText: resp.statusText, headers: newHeaders });
    }
  } catch(e){}
  return resp;
}

// ---------------------------
// Security Authenticate Intercept
// ---------------------------
async function handleAuthenticateIntercept(resp, env, url, request) {
  try {
    const buf = await resp.clone().arrayBuffer();
    const text = new TextDecoder().decode(buf);
    const json = JSON.parse(text);
    if (json?.status === true && json?.account?.token) {
      const secureToken = await generateSecureToken(json.account.token, env);
      const origin = request.headers.get('Origin') || '';
      const subdomain = getSubdomain(origin ? new URL(origin).host : url.host, env.MAIN_DOMAIN);
      const cookieName = subdomain ? subdomain + cookieSuffix : accountTokenCookie;
      const setCookie = makeSetCookieHeader(cookieName, secureToken, '.' + env.MAIN_DOMAIN, tokenExpirySeconds);

      var fakeToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJsZW1vcmFzIiwiaWF0IjoxNTg";
            fakeToken = fakeToken + "4OTUyMjk1LCJleHAiOjE5MDQ0ODUwOTUsImF1ZCI6ImtpbWxpay5vbmxpbmUiLCJzdWIi";
            fakeToken = fakeToken + "OiJvbnVyQHlhc2FyLmVtYWlsIiwiR2l2ZW5OYW1lIjoiT251ciIsIlN1cm5hbWUiOiJZYX";
            fakeToken = fakeToken + "NhciIsIkVtYWlsIjoib251ckB5YXNhci5lbWFpbCIsIlJvbGUiOiJTb2x1dGlvbiBBcmNoa";
            fakeToken = fakeToken + "XRlY3QifQ.GsruHtt1Sk1tlRJPBEmnNFuMJ_jVPr_DK84mDgyhBZ0";

      json.account.token = fakeToken;
      const newBody = new TextEncoder().encode(JSON.stringify(json));
      const newHeaders = new Headers(resp.headers);
      newHeaders.append('Set-Cookie', setCookie);
      newHeaders.delete('Content-Length');
      return new Response(newBody, { status: resp.status, statusText: resp.statusText, headers: newHeaders });
    }
  } catch(e){}
  return resp;
}

// ---------------------------
// Main Fetch
// ---------------------------
export default {
  async fetch(request, env) {
    await initKeys(env);

    const url = new URL(request.url);
    const path = url.pathname;

    const origin = validateCORS(request);
    if (!origin) return new Response('CORS origin not allowed', { status: 403 });
    if (request.method === 'OPTIONS') return withCORS(new Response(null, { status: 200 }), origin);

    if (path === '/api/logout') return handleLogout(request, env);

    // Rate limiting
    let ipAddr = request.headers.get("CF-Connecting-IP") || "unknown";
    const cookieHeader = request.headers.get('cookie') || '';
    const cookies = parseCookies(cookieHeader);
    let cookieVal = cookies[accountTokenCookie] || '';
    let rateKey = ipAddr;
    let maxReq = normalRateLimit;

    if (cookieVal) {
      try { const result = await cachedValidateToken(cookieVal, env); rateKey = `${ipAddr}_${result.token}`; } catch(e){}
    }

    for (const t of trustedURLs) {
      if (url.href === t.url) maxReq = t.limit !== Infinity ? t.limit : maxReq;
    }
    if (path.includes('security/validation') && maxReq !== Infinity) maxReq = validationRateLimit;

    if (maxReq !== Infinity) {
      const allowed = await cachedAllowRequestKV(env, `rate-limit:${rateKey}:${url.pathname}`, maxReq, rateLimitWindowSeconds);
      if (!allowed) return withCORS(new Response('⛔ Too Many Requests',{status:429}), origin);
    }

    let targetBase = env.SERVICE_TARGET_URL;
    if (path.startsWith('/system')) targetBase = env.SYSTEM_TARGET_URL;
    else if (path.startsWith('/security')) targetBase = env.SECURITY_TARGET_URL;
    else if (path.startsWith('/file/')) targetBase = env.FILE_TARGET_URL;

    let resp = await handleProxy(request, targetBase, env);

    if (path.includes('/security/authenticate')) resp = await handleAuthenticateIntercept(resp, env, url, request);
    resp = await handleTokenRenewal(request, env, resp);
    resp = withCORS(resp, origin);

    return resp;
  }
};
