// IAM Lab · servidor de autorización OAuth 2.0 / OpenID Connect de laboratorio.
//
// Es un servidor DIDÁCTICO: implementa el flujo Authorization Code + PKCE de
// verdad (firma ES256, discovery, JWKS, userinfo), pero con simplificaciones
// deliberadas que la propia web explica (usuario de prueba fijo, un único
// cliente público y códigos de autorización sin estado). No lo uses como IdP real.

const CLIENT_ID = "lab-spa";
const SCOPES = ["openid", "profile", "email"];
const CODE_TTL = 60; // segundos
const TOKEN_TTL = 600; // segundos
const DEMO_USER = {
  sub: "usr_7f3a9c",
  name: "Alex Prueba",
  given_name: "Alex",
  family_name: "Prueba",
  email: "alex@lab.spliter.dev",
  email_verified: true,
};

// ---------- utilidades ----------

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64url(bytes) {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(str) {
  const s = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4 ? "=".repeat(4 - (s.length % 4)) : "";
  const bin = atob(s + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const now = () => Math.floor(Date.now() / 1000);

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extra,
    },
  });
}

function oauthError(error, description, status = 400) {
  return json({ error, error_description: description }, status);
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

// ---------- claves ----------

let keyCache = null;

async function getKeys(env) {
  if (keyCache) return keyCache;
  let privateJwk;
  let ephemeral = false;
  if (env && env.PRIVATE_JWK) {
    privateJwk = JSON.parse(env.PRIVATE_JWK);
  } else {
    // Sin secreto configurado: clave efímera por instancia. Funciona para
    // pruebas, pero los tokens pueden dejar de verificarse si Cloudflare
    // reparte las peticiones entre instancias distintas.
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
    ephemeral = true;
  }
  const privateKey = await crypto.subtle.importKey("jwk", privateJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const { d, key_ops, ext, ...pub } = privateJwk;
  const publicJwk = { ...pub, use: "sig", alg: "ES256" };
  publicJwk.kid = publicJwk.kid || (await thumbprint(publicJwk));
  const publicKey = await crypto.subtle.importKey("jwk", { kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  keyCache = { privateKey, publicKey, publicJwk, ephemeral };
  return keyCache;
}

async function thumbprint(jwk) {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return b64url(await crypto.subtle.digest("SHA-256", enc.encode(canonical)));
}

async function signJwt(env, payload, typ = "JWT") {
  const { privateKey, publicJwk } = await getKeys(env);
  const header = { alg: "ES256", typ, kid: publicJwk.kid };
  const input = `${b64url(enc.encode(JSON.stringify(header)))}.${b64url(enc.encode(JSON.stringify(payload)))}`;
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, enc.encode(input));
  return `${input}.${b64url(sig)}`;
}

async function verifyJwt(env, token, expectedTyp) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) return { ok: false, reason: "formato no válido" };
  let header, payload;
  try {
    header = JSON.parse(dec.decode(b64urlDecode(parts[0])));
    payload = JSON.parse(dec.decode(b64urlDecode(parts[1])));
  } catch {
    return { ok: false, reason: "no se puede decodificar" };
  }
  if (header.alg !== "ES256") return { ok: false, reason: `algoritmo no permitido: ${header.alg}` };
  if (expectedTyp && header.typ !== expectedTyp) return { ok: false, reason: `tipo inesperado: ${header.typ}` };
  const { publicKey } = await getKeys(env);
  const valid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    b64urlDecode(parts[2]),
    enc.encode(`${parts[0]}.${parts[1]}`)
  );
  if (!valid) return { ok: false, reason: "firma no válida" };
  if (typeof payload.exp === "number" && payload.exp < now()) return { ok: false, reason: "caducado", payload };
  return { ok: true, header, payload };
}

async function s256(verifier) {
  return b64url(await crypto.subtle.digest("SHA-256", enc.encode(verifier)));
}

// ---------- endpoints ----------

function discovery(origin) {
  return {
    issuer: origin,
    authorization_endpoint: `${origin}/as/authorize`,
    token_endpoint: `${origin}/as/token`,
    userinfo_endpoint: `${origin}/as/userinfo`,
    jwks_uri: `${origin}/as/jwks`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["ES256"],
    scopes_supported: SCOPES,
    token_endpoint_auth_methods_supported: ["none"],
    code_challenge_methods_supported: ["S256"],
    claims_supported: ["sub", "name", "given_name", "family_name", "email", "email_verified", "nonce"],
  };
}

function validateAuthorizeParams(p, origin) {
  const redirectUri = `${origin}/`;
  // Errores que NO se pueden devolver al cliente por redirección (RFC 6749 §4.1.2.1):
  if (p.get("client_id") !== CLIENT_ID) return { fatal: `client_id desconocido: "${p.get("client_id") || ""}"` };
  if (p.get("redirect_uri") !== redirectUri)
    return { fatal: `redirect_uri no registrada: "${p.get("redirect_uri") || ""}". La única permitida es ${redirectUri}` };
  // Errores que sí se devuelven al cliente:
  if (p.get("response_type") !== "code") return { error: "unsupported_response_type", desc: "Solo se admite response_type=code" };
  const scopes = (p.get("scope") || "").split(" ").filter(Boolean);
  if (!scopes.includes("openid")) return { error: "invalid_scope", desc: "Falta el scope openid" };
  if (scopes.some((s) => !SCOPES.includes(s))) return { error: "invalid_scope", desc: "Scope no admitido" };
  if (!p.get("code_challenge") || p.get("code_challenge_method") !== "S256")
    return { error: "invalid_request", desc: "PKCE obligatorio: falta code_challenge con método S256" };
  return { ok: true, scopes };
}

function redirectWith(redirectUri, params) {
  const u = new URL(redirectUri);
  for (const [k, v] of Object.entries(params)) if (v != null && v !== "") u.searchParams.set(k, v);
  return Response.redirect(u.toString(), 302);
}

async function authorize(request, url, env) {
  const origin = url.origin;
  const p = request.method === "POST" ? new URLSearchParams(await request.text()) : url.searchParams;
  const check = validateAuthorizeParams(p, origin);
  if (check.fatal) return htmlPage("Solicitud rechazada", errorBody(check.fatal), 400);
  if (check.error) return redirectWith(p.get("redirect_uri"), { error: check.error, error_description: check.desc, state: p.get("state") });

  if (request.method === "GET") return htmlPage("Iniciar sesión · IAM Lab", consentBody(p, check.scopes));

  // POST: el usuario ha respondido en la pantalla de consentimiento.
  if (p.get("decision") !== "allow")
    return redirectWith(p.get("redirect_uri"), { error: "access_denied", error_description: "El usuario ha rechazado el acceso", state: p.get("state") });

  const code = await signJwt(
    env,
    {
      iss: origin,
      aud: CLIENT_ID,
      sub: DEMO_USER.sub,
      redirect_uri: p.get("redirect_uri"),
      scope: check.scopes.join(" "),
      nonce: p.get("nonce") || undefined,
      code_challenge: p.get("code_challenge"),
      iat: now(),
      exp: now() + CODE_TTL,
    },
    "authz-code"
  );
  return redirectWith(p.get("redirect_uri"), { code, state: p.get("state") });
}

async function token(request, url, env) {
  if (request.method !== "POST") return oauthError("invalid_request", "Usa POST", 405);
  const ct = request.headers.get("content-type") || "";
  if (!ct.includes("application/x-www-form-urlencoded"))
    return oauthError("invalid_request", "El cuerpo debe ser application/x-www-form-urlencoded");
  const p = new URLSearchParams(await request.text());
  if (p.get("grant_type") !== "authorization_code") return oauthError("unsupported_grant_type", "Solo se admite authorization_code");
  if (p.get("client_id") !== CLIENT_ID) return oauthError("invalid_client", "client_id desconocido", 401);

  const v = await verifyJwt(env, p.get("code"), "authz-code");
  if (!v.ok) return oauthError("invalid_grant", `Código de autorización no válido (${v.reason})`);
  const c = v.payload;
  if (c.aud !== CLIENT_ID) return oauthError("invalid_grant", "El código no se emitió para este cliente");
  if (p.get("redirect_uri") !== c.redirect_uri)
    return oauthError("invalid_grant", "redirect_uri no coincide con la usada al pedir el código");
  const verifier = p.get("code_verifier") || "";
  if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(verifier)) return oauthError("invalid_grant", "code_verifier con formato no válido");
  if ((await s256(verifier)) !== c.code_challenge)
    return oauthError("invalid_grant", "PKCE: SHA-256(code_verifier) no coincide con el code_challenge");

  const origin = url.origin;
  const iat = now();
  const accessToken = await signJwt(
    env,
    { iss: origin, aud: `${origin}/as/userinfo`, sub: c.sub, client_id: CLIENT_ID, scope: c.scope, iat, exp: iat + TOKEN_TTL, jti: crypto.randomUUID() },
    "at+jwt"
  );
  const scopes = c.scope.split(" ");
  const idClaims = { iss: origin, aud: CLIENT_ID, sub: c.sub, iat, exp: iat + TOKEN_TTL, auth_time: c.iat, nonce: c.nonce };
  if (scopes.includes("profile")) Object.assign(idClaims, { name: DEMO_USER.name });
  if (scopes.includes("email")) Object.assign(idClaims, { email: DEMO_USER.email, email_verified: DEMO_USER.email_verified });
  const idToken = await signJwt(env, idClaims, "JWT");

  return json({ access_token: accessToken, token_type: "Bearer", expires_in: TOKEN_TTL, scope: c.scope, id_token: idToken }, 200, { pragma: "no-cache" });
}

async function userinfo(request, url, env) {
  const auth = request.headers.get("authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  const challenge = (err, desc) => ({ "www-authenticate": `Bearer error="${err}", error_description="${desc}"` });
  if (!m) return json({ error: "invalid_token", error_description: "Falta el token Bearer" }, 401, challenge("invalid_request", "Falta el token"));
  const v = await verifyJwt(env, m[1], "at+jwt");
  if (!v.ok) return json({ error: "invalid_token", error_description: `Token no válido (${v.reason})` }, 401, challenge("invalid_token", v.reason));
  if (v.payload.aud !== `${url.origin}/as/userinfo`) return json({ error: "invalid_token", error_description: "Audiencia incorrecta" }, 401);
  const scopes = v.payload.scope.split(" ");
  const out = { sub: v.payload.sub };
  if (scopes.includes("profile")) Object.assign(out, { name: DEMO_USER.name, given_name: DEMO_USER.given_name, family_name: DEMO_USER.family_name });
  if (scopes.includes("email")) Object.assign(out, { email: DEMO_USER.email, email_verified: DEMO_USER.email_verified });
  return json(out);
}

// ---------- páginas del servidor de autorización ----------

function htmlPage(title, body, status = 200) {
  return new Response(
    `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(title)}</title><link rel="stylesheet" href="/styles.css"><link rel="icon" href="https://spliter.dev/brand/favicon.ico"></head><body class="as-page"><main class="as-card">${body}</main></body></html>`,
    {
      status,
      headers: {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        "x-frame-options": "DENY",
        "content-security-policy": "default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' https://spliter.dev; frame-ancestors 'none'; form-action 'self'",
      },
    }
  );
}

function errorBody(message) {
  return `<p class="as-kicker">Servidor de autorización</p><h1>Solicitud rechazada</h1><p>${escapeHtml(message)}</p><p class="as-note">Cuando el problema está en <code>client_id</code> o <code>redirect_uri</code>, el servidor no redirige de vuelta: no puede fiarse de a dónde mandar al usuario. Por eso ves este error aquí y no en la aplicación.</p><p><a class="btn" href="/">Volver al laboratorio</a></p>`;
}

function consentBody(p, scopes) {
  const hidden = [...p.entries()].map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`).join("");
  const labels = { openid: "Saber quién eres (identificador)", profile: "Tu nombre", email: "Tu correo electrónico" };
  const items = scopes.map((s) => `<li><code>${escapeHtml(s)}</code> ${escapeHtml(labels[s] || s)}</li>`).join("");
  return `<p class="as-kicker">Servidor de autorización · IAM Lab</p>
<h1>¿Permitir el acceso a «Lab SPA»?</h1>
<p>Has iniciado sesión como <strong>${escapeHtml(DEMO_USER.name)}</strong> (${escapeHtml(DEMO_USER.email)}), un usuario de prueba.</p>
<p>La aplicación pide:</p><ul class="as-scopes">${items}</ul>
<form method="post" action="/as/authorize">${hidden}
<div class="as-actions"><button class="btn btn-primary" name="decision" value="allow">Permitir</button><button class="btn" name="decision" value="deny">Rechazar</button></div>
</form>
<p class="as-note">Esta pantalla pertenece al servidor de autorización, no a la aplicación. La aplicación nunca ve tu contraseña: solo recibirá un código de un solo uso.</p>`;
}

// ---------- router ----------

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    try {
      if (path === "/.well-known/openid-configuration") return json(discovery(url.origin), 200, { "access-control-allow-origin": "*" });
      if (path === "/as/jwks") {
        const { publicJwk, ephemeral } = await getKeys(env);
        return json({ keys: [publicJwk] }, 200, { "access-control-allow-origin": "*", "x-lab-ephemeral-key": String(ephemeral) });
      }
      if (path === "/as/authorize") return await authorize(request, url, env);
      if (path === "/as/token") return await token(request, url, env);
      if (path === "/as/userinfo") return await userinfo(request, url, env);
      if (env && env.ASSETS) return env.ASSETS.fetch(request);
      return new Response("Not found", { status: 404 });
    } catch (err) {
      return json({ error: "server_error", error_description: "Error interno del laboratorio" }, 500);
    }
  },
};

// Exportado solo para los tests.
export const _internal = { b64url, b64urlDecode, s256, CLIENT_ID, resetKeys: () => (keyCache = null) };
