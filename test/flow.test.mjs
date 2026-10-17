// Tests del flujo completo contra el Worker, sin Cloudflare: node --test test/
import { test } from "node:test";
import assert from "node:assert/strict";
import worker, { _internal } from "../src/worker.js";

const ORIGIN = "https://lab.example";
const env = {};
const call = (path, init) => worker.fetch(new Request(ORIGIN + path, { redirect: "manual", ...init }), env);

function rand() {
  return _internal.b64url(crypto.getRandomValues(new Uint8Array(32)));
}

async function getCode({ verifier, state = "st", nonce = "nn", redirect = ORIGIN + "/" } = {}) {
  const challenge = await _internal.s256(verifier);
  const body = new URLSearchParams({
    response_type: "code", client_id: "lab-spa", redirect_uri: redirect, scope: "openid profile email",
    state, nonce, code_challenge: challenge, code_challenge_method: "S256", decision: "allow",
  });
  const res = await call("/as/authorize", { method: "POST", body, headers: { "content-type": "application/x-www-form-urlencoded" } });
  return res;
}

const exchange = (code, verifier, redirect = ORIGIN + "/") =>
  call("/as/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", client_id: "lab-spa", code, code_verifier: verifier, redirect_uri: redirect }),
  });

test("discovery y jwks", async () => {
  const d = await (await call("/.well-known/openid-configuration")).json();
  assert.equal(d.issuer, ORIGIN);
  assert.deepEqual(d.code_challenge_methods_supported, ["S256"]);
  const j = await (await call("/as/jwks")).json();
  assert.equal(j.keys[0].alg, "ES256");
  assert.equal(j.keys[0].d, undefined, "la JWKS no debe exponer la clave privada");
});

test("authorize GET muestra consentimiento", async () => {
  const q = new URLSearchParams({ response_type: "code", client_id: "lab-spa", redirect_uri: ORIGIN + "/", scope: "openid", state: "s", code_challenge: "x".repeat(43), code_challenge_method: "S256" });
  const res = await call("/as/authorize?" + q);
  assert.equal(res.status, 200);
  assert.match(await res.text(), /Permitir/);
});

test("redirect_uri no registrada no redirige", async () => {
  const q = new URLSearchParams({ response_type: "code", client_id: "lab-spa", redirect_uri: "https://evil.example/", scope: "openid", code_challenge: "x".repeat(43), code_challenge_method: "S256" });
  const res = await call("/as/authorize?" + q);
  assert.equal(res.status, 400);
});

test("flujo completo con PKCE", async () => {
  const verifier = rand();
  const res = await getCode({ verifier });
  assert.equal(res.status, 302);
  const loc = new URL(res.headers.get("location"));
  assert.equal(loc.searchParams.get("state"), "st");
  const code = loc.searchParams.get("code");
  const tok = await exchange(code, verifier);
  assert.equal(tok.status, 200);
  const t = await tok.json();
  assert.equal(t.token_type, "Bearer");
  const idPayload = JSON.parse(new TextDecoder().decode(_internal.b64urlDecode(t.id_token.split(".")[1])));
  assert.equal(idPayload.nonce, "nn");
  assert.equal(idPayload.aud, "lab-spa");
  const ui = await call("/as/userinfo", { headers: { authorization: "Bearer " + t.access_token } });
  assert.equal(ui.status, 200);
  assert.equal((await ui.json()).email, "alex@lab.spliter.dev");
  // el id_token no sirve como access token
  const bad = await call("/as/userinfo", { headers: { authorization: "Bearer " + t.id_token } });
  assert.equal(bad.status, 401);
});

test("verifier incorrecto -> invalid_grant", async () => {
  const verifier = rand();
  const code = new URL((await getCode({ verifier })).headers.get("location")).searchParams.get("code");
  const tok = await exchange(code, rand());
  assert.equal(tok.status, 400);
  assert.equal((await tok.json()).error, "invalid_grant");
});

test("redirect_uri distinta en /token -> invalid_grant", async () => {
  const verifier = rand();
  const code = new URL((await getCode({ verifier })).headers.get("location")).searchParams.get("code");
  const tok = await exchange(code, verifier, ORIGIN + "/otra");
  assert.equal((await tok.json()).error, "invalid_grant");
});

test("access token manipulado -> 401", async () => {
  const verifier = rand();
  const code = new URL((await getCode({ verifier })).headers.get("location")).searchParams.get("code");
  const t = await (await exchange(code, verifier)).json();
  const [h, p, s] = t.access_token.split(".");
  const payload = JSON.parse(new TextDecoder().decode(_internal.b64urlDecode(p)));
  payload.scope = "openid profile email admin";
  const forged = `${h}.${_internal.b64url(new TextEncoder().encode(JSON.stringify(payload)))}.${s}`;
  const ui = await call("/as/userinfo", { headers: { authorization: "Bearer " + forged } });
  assert.equal(ui.status, 401);
});

test("alg none rechazado", async () => {
  const h = _internal.b64url(new TextEncoder().encode(JSON.stringify({ alg: "none", typ: "at+jwt" })));
  const p = _internal.b64url(new TextEncoder().encode(JSON.stringify({ sub: "x", scope: "openid", aud: ORIGIN + "/as/userinfo" })));
  const ui = await call("/as/userinfo", { headers: { authorization: `Bearer ${h}.${p}.` } });
  assert.equal(ui.status, 401);
});

test("rechazo del usuario -> access_denied con state", async () => {
  const body = new URLSearchParams({ response_type: "code", client_id: "lab-spa", redirect_uri: ORIGIN + "/", scope: "openid", state: "zz", code_challenge: "x".repeat(43), code_challenge_method: "S256", decision: "deny" });
  const res = await call("/as/authorize", { method: "POST", body, headers: { "content-type": "application/x-www-form-urlencoded" } });
  const loc = new URL(res.headers.get("location"));
  assert.equal(loc.searchParams.get("error"), "access_denied");
  assert.equal(loc.searchParams.get("state"), "zz");
});

// ---------- proveedor de identidad para el Authz Lab ----------

const AUTHZ_REDIRECT = "https://authz.spliter.dev/callback";

async function authzCode({ verifier, user = "usr_carla", mfa = false, redirect = AUTHZ_REDIRECT }) {
  const body = new URLSearchParams({
    response_type: "code", client_id: "authz-lab", redirect_uri: redirect, scope: "openid profile email",
    state: "s", nonce: "n", code_challenge: await _internal.s256(verifier), code_challenge_method: "S256",
    decision: "allow", login_user: user, ...(mfa ? { mfa: "on" } : {}),
  });
  return call("/as/authorize", { method: "POST", body, headers: { "content-type": "application/x-www-form-urlencoded" } });
}

const claims = (jwt) => JSON.parse(new TextDecoder().decode(_internal.b64urlDecode(jwt.split(".")[1])));

test("authz-lab: usuario elegido y MFA llegan al id_token", async () => {
  const verifier = rand();
  const res = await authzCode({ verifier, user: "usr_ana", mfa: true });
  assert.equal(res.status, 302);
  const loc = new URL(res.headers.get("location"));
  assert.equal(loc.origin + loc.pathname, AUTHZ_REDIRECT);
  const tok = await call("/as/token", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", client_id: "authz-lab", code: loc.searchParams.get("code"), code_verifier: verifier, redirect_uri: AUTHZ_REDIRECT }),
  });
  assert.equal(tok.status, 200);
  const id = claims((await tok.json()).id_token);
  assert.equal(id.sub, "usr_ana");
  assert.equal(id.aud, "authz-lab");
  assert.equal(id.name, "Ana Torres");
  assert.ok(id.amr.includes("mfa"));
});

test("sin MFA, amr solo contiene pwd", async () => {
  const verifier = rand();
  const loc = new URL((await authzCode({ verifier })).headers.get("location"));
  const tok = await call("/as/token", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", client_id: "authz-lab", code: loc.searchParams.get("code"), code_verifier: verifier, redirect_uri: AUTHZ_REDIRECT }),
  });
  assert.deepEqual(claims((await tok.json()).id_token).amr, ["pwd"]);
});

test("un código de authz-lab no se puede canjear como lab-spa", async () => {
  const verifier = rand();
  const loc = new URL((await authzCode({ verifier })).headers.get("location"));
  const tok = await call("/as/token", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", client_id: "lab-spa", code: loc.searchParams.get("code"), code_verifier: verifier, redirect_uri: AUTHZ_REDIRECT }),
  });
  assert.equal((await tok.json()).error, "invalid_grant");
});

test("authz-lab no puede usar la redirect_uri de lab-spa", async () => {
  const q = new URLSearchParams({ response_type: "code", client_id: "authz-lab", redirect_uri: ORIGIN + "/", scope: "openid", code_challenge: "x".repeat(43), code_challenge_method: "S256" });
  assert.equal((await call("/as/authorize?" + q)).status, 400);
});

test("la pantalla de consentimiento lista los usuarios de prueba", async () => {
  const q = new URLSearchParams({ response_type: "code", client_id: "authz-lab", redirect_uri: AUTHZ_REDIRECT, scope: "openid", code_challenge: "x".repeat(43), code_challenge_method: "S256" });
  const html = await (await call("/as/authorize?" + q)).text();
  assert.match(html, /Authz Lab/);
  assert.match(html, /Bruno Gil/);
  assert.match(html, /name="mfa"/);
});

test("CSP del consentimiento permite redirigir al cliente registrado", async () => {
  const q = new URLSearchParams({ response_type: "code", client_id: "authz-lab", redirect_uri: AUTHZ_REDIRECT, scope: "openid", code_challenge: "x".repeat(43), code_challenge_method: "S256" });
  const csp = (await call("/as/authorize?" + q)).headers.get("content-security-policy");
  assert.match(csp, /form-action 'self' https:\/\/authz\.spliter\.dev(;|$)/);
  const q2 = new URLSearchParams({ response_type: "code", client_id: "lab-spa", redirect_uri: ORIGIN + "/", scope: "openid", code_challenge: "x".repeat(43), code_challenge_method: "S256" });
  assert.match((await call("/as/authorize?" + q2)).headers.get("content-security-policy"), /form-action 'self' https:\/\/lab\.example/);
});
