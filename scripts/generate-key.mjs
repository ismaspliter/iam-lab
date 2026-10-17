// Genera la clave privada de firma (EC P-256) para el secreto PRIVATE_JWK.
// Uso: node scripts/generate-key.mjs
// Copia la línea que imprime y pégala como secreto en Cloudflare. No la subas al repo.
const { privateKey } = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const jwk = await crypto.subtle.exportKey("jwk", privateKey);
const { kty, crv, x, y, d } = jwk;
console.log(JSON.stringify({ kty, crv, x, y, d }));
