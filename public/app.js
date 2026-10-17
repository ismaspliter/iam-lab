// IAM Lab · cliente (la "aplicación"): una SPA pública que usa Authorization Code + PKCE.

const CLIENT_ID = "lab-spa";
const ORIGIN = location.origin;
const REDIRECT_URI = ORIGIN + "/";
const SCOPE = "openid profile email";
const KEY = "iamlab";
const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();
const dec = new TextDecoder();

// ---------- utilidades ----------
const b64url = (bytes) => {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
const b64urlDecode = (str) => {
  const s = str.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(s + "=".repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};
const random = (n = 32) => b64url(crypto.getRandomValues(new Uint8Array(n)));
const sha256 = async (s) => b64url(await crypto.subtle.digest("SHA-256", enc.encode(s)));
const pretty = (o) => JSON.stringify(o, null, 2);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

const load = () => { try { return JSON.parse(sessionStorage.getItem(KEY)) || {}; } catch { return {}; } };
const save = (s) => { try { sessionStorage.setItem(KEY, JSON.stringify(s)); } catch {} };
let st = load();

function enable(id, on = true) {
  $(id).setAttribute("aria-disabled", on ? "false" : "true");
}
function result(ok, title, body) {
  return `<div class="result ${ok ? "ok" : "bad"}"><strong>${ok ? "✓" : "✕"} ${esc(title)}</strong>${body ? `<p>${body}</p>` : ""}</div>`;
}
function showUrl(el, url) {
  const u = new URL(url);
  const params = [...u.searchParams.entries()]
    .map(([k, v]) => `  <span class="k">${esc(k)}</span>=<span class="v">${esc(v)}</span>`)
    .join("\n&");
  el.innerHTML = `<span class="m">GET</span> ${esc(u.origin + u.pathname)}?\n${params}`;
}

// ---------- paso 1 ----------
async function prepare(fresh = false) {
  if (fresh || !st.verifier) {
    st = { verifier: random(32), state: random(16), nonce: random(16) };
    st.challenge = await sha256(st.verifier);
    save(st);
  }
  $("s1-values").innerHTML = [
    ["state", st.state, "se queda en la app"],
    ["nonce", st.nonce, "viaja y vuelve dentro del id_token"],
    ["code_verifier", st.verifier, "secreto: no sale todavía de la app"],
    ["code_challenge", st.challenge, "= BASE64URL(SHA-256(code_verifier))"],
  ].map(([k, v, n]) => `<div><dt><code>${k}</code></dt><dd><span class="mono">${esc(v)}</span><small>${n}</small></dd></div>`).join("");
  showUrl($("s1-url"), authorizeUrl());
}

function authorizeUrl() {
  const u = new URL(ORIGIN + "/as/authorize");
  const redirect = $("opt-redirect").checked ? "https://atacante.example/robar" : REDIRECT_URI;
  Object.entries({
    response_type: "code", client_id: CLIENT_ID, redirect_uri: redirect, scope: SCOPE,
    state: st.state, nonce: st.nonce, code_challenge: st.challenge, code_challenge_method: "S256",
  }).forEach(([k, v]) => u.searchParams.set(k, v));
  return u.toString();
}

$("opt-redirect").addEventListener("change", () => showUrl($("s1-url"), authorizeUrl()));
$("regen").addEventListener("click", () => prepare(true));
$("go-authorize").addEventListener("click", () => {
  st.csrf = $("opt-csrf").checked;
  delete st.code; delete st.tokens; delete st.callback;
  save(st);
  location.assign(authorizeUrl());
});

// ---------- paso 2 ----------
function handleCallback() {
  const q = new URLSearchParams(location.search);
  if (!q.has("code") && !q.has("error")) return false;
  st.callback = location.href;
  history.replaceState(null, "", "/");
  const returnedState = st.csrf ? "estado-falso-del-atacante" : q.get("state");
  enable("s2");
  const shown = new URL(st.callback);
  if (st.csrf) shown.searchParams.set("state", returnedState);
  showUrl($("s2-url"), shown.toString());
  $("s2-url").innerHTML = $("s2-url").innerHTML.replace('<span class="m">GET</span>', '<span class="m">→</span>');

  if (q.has("error")) {
    $("s2-check").innerHTML = result(false, `El servidor devolvió un error: ${q.get("error")}`, esc(q.get("error_description") || ""));
    save(st);
    return true;
  }
  if (returnedState !== st.state) {
    $("s2-check").innerHTML = result(false, "state no coincide: respuesta descartada",
      `La app esperaba <code>${esc(st.state)}</code> y ha recibido <code>${esc(returnedState)}</code>. Esta respuesta no viene de un inicio de sesión que ella haya empezado: podría ser un atacante intentando colarte su propia sesión (login CSRF). No se canjea el código.`);
    save(st);
    return true;
  }
  st.code = q.get("code");
  save(st);
  $("s2-check").innerHTML = result(true, "state correcto", "La respuesta corresponde a la petición que inició esta app. Siguiente paso: canjear el código.");
  enable("s3");
  renderTokenRequest();
  return true;
}

// ---------- paso 3 ----------
function tokenBody() {
  return new URLSearchParams({
    grant_type: "authorization_code", client_id: CLIENT_ID, code: st.code, redirect_uri: REDIRECT_URI,
    code_verifier: $("opt-verifier").checked ? random(32) : st.verifier,
  });
}
function renderTokenRequest() {
  const body = [...tokenBody().entries()].map(([k, v]) => `<span class="k">${esc(k)}</span>=<span class="v">${esc(v)}</span>`).join("\n&");
  $("s3-req").innerHTML = `<span class="m">POST</span> ${esc(ORIGIN)}/as/token\nContent-Type: application/x-www-form-urlencoded\n\n${body}`;
}
$("opt-verifier").addEventListener("change", renderTokenRequest);
$("go-token").addEventListener("click", async () => {
  $("s3-res").textContent = "Enviando…";
  const res = await fetch("/as/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: tokenBody() });
  const data = await res.json();
  $("s3-res").innerHTML = `<span class="m">HTTP ${res.status}</span>\n${esc(pretty(data))}`;
  if (res.ok) {
    st.tokens = data;
    save(st);
    enable("s4"); enable("s5");
    showToken("id_token");
  } else {
    $("s3-res").insertAdjacentHTML("afterend", "");
  }
});

// ---------- paso 4 ----------
let current = "id_token";
let override = null;
let jwksKey = null;

async function publicKey() {
  if (jwksKey) return jwksKey;
  const { keys } = await (await fetch("/as/jwks")).json();
  const k = keys[0];
  jwksKey = await crypto.subtle.importKey("jwk", { kty: k.kty, crv: k.crv, x: k.x, y: k.y }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  return jwksKey;
}

async function showToken(name, tokenOverride) {
  current = name;
  override = tokenOverride || null;
  document.querySelectorAll(".tab").forEach((t) => t.setAttribute("aria-selected", String(t.dataset.tok === name)));
  const token = override || st.tokens[name];
  const [h, p, s] = token.split(".");
  $("s4-raw").innerHTML = `<span class="jwt-h">${esc(h)}</span>.<span class="jwt-p">${esc(p)}</span>.<span class="jwt-s">${esc(s)}</span>`;
  const header = JSON.parse(dec.decode(b64urlDecode(h)));
  const payload = JSON.parse(dec.decode(b64urlDecode(p)));
  $("s4-header").textContent = pretty(header);
  $("s4-payload").textContent = pretty(payload);

  const sigOk = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, await publicKey(), b64urlDecode(s), enc.encode(`${h}.${p}`));
  const t = Math.floor(Date.now() / 1000);
  const checks = [
    [header.alg === "ES256", `Algoritmo esperado (ES256)`, `alg = ${header.alg}`],
    [sigOk, "Firma válida con la clave pública del JWKS", sigOk ? "Nadie ha modificado el token desde que lo firmó el servidor." : "El contenido no corresponde a la firma: el token se ha manipulado."],
    [payload.iss === ORIGIN, "Emisor (iss) es nuestro servidor", payload.iss],
    [payload.exp > t, "No ha caducado (exp)", `caduca en ${payload.exp - t} s`],
  ];
  if (name === "id_token") {
    checks.push([payload.aud === CLIENT_ID, "Audiencia (aud) es esta aplicación", payload.aud]);
    checks.push([payload.nonce === st.nonce, "nonce coincide con el del paso 1", payload.nonce]);
  } else {
    checks.push([true, "La app no necesita validar el access_token", "Es opaco para el cliente: lo valida la API que lo recibe (aquí, /userinfo)."]);
  }
  $("s4-checks").innerHTML = checks.map(([ok, title, d]) => `<li class="${ok ? "ok" : "bad"}"><strong>${ok ? "✓" : "✕"} ${esc(title)}</strong><small>${esc(d)}</small></li>`).join("");
}

document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => showToken(t.dataset.tok)));
$("tamper").addEventListener("click", () => {
  const token = override || st.tokens[current];
  const [h, p, s] = token.split(".");
  const payload = JSON.parse(dec.decode(b64urlDecode(p)));
  if (current === "id_token") payload.email = "admin@lab.spliter.dev";
  else payload.scope += " admin";
  showToken(current, `${h}.${b64url(enc.encode(JSON.stringify(payload)))}.${s}`);
});
$("restore").addEventListener("click", () => showToken(current));

// ---------- paso 5 ----------
document.querySelectorAll("[data-ui]").forEach((b) =>
  b.addEventListener("click", async () => {
    const which = b.dataset.ui;
    const headers = {};
    let shown = "(sin cabecera Authorization)";
    if (which !== "none") {
      const tok = which === "access_token" && override && current === "access_token" ? override : st.tokens[which];
      headers.authorization = `Bearer ${tok}`;
      shown = `Authorization: Bearer ${tok.slice(0, 24)}…`;
    }
    const res = await fetch("/as/userinfo", { headers });
    const www = res.headers.get("www-authenticate");
    $("s5-res").innerHTML = `<span class="m">GET</span> /as/userinfo\n${esc(shown)}\n\n<span class="m">HTTP ${res.status}</span>${www ? `\nWWW-Authenticate: ${esc(www)}` : ""}\n${esc(pretty(await res.json()))}`;
  })
);

// ---------- arranque ----------
(async () => {
  await prepare(false);
  if (!handleCallback() && st.code) {
    // Recarga en mitad del flujo: restaurar lo que haya.
    enable("s2");
    $("s2-check").innerHTML = result(true, "Código recibido previamente", "");
    enable("s3");
    renderTokenRequest();
  }
  if (st.tokens) {
    enable("s4"); enable("s5");
    showToken("id_token");
  }
  if (st.callback || st.tokens) document.getElementById(st.tokens ? "s4" : "s2").scrollIntoView({ block: "start" });
})();
