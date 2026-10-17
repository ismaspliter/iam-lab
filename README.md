# IAM Lab

Laboratorio interactivo de **OAuth 2.0 y OpenID Connect**: recorre un inicio de sesión real con *Authorization Code + PKCE*, inspecciona cada petición y cada token, y rompe el flujo a propósito para ver cómo se defiende.

**→ [lab.spliter.dev](https://lab.spliter.dev)**

## Qué incluye

- **Servidor de autorización de laboratorio** en un Cloudflare Worker: discovery (`/.well-known/openid-configuration`), JWKS, `/authorize` con pantalla de consentimiento, `/token` y `/userinfo`. Tokens JWT firmados de verdad con **ES256**.
- **Cliente SPA** que hace el flujo paso a paso y muestra:
  1. Generación de `state`, `nonce` y PKCE (`code_verifier` → `code_challenge`).
  2. Vuelta con el código y comprobación del `state`.
  3. Canje del código en `/token`.
  4. Decodificación y validación del `id_token` y del `access_token` contra el JWKS.
  5. Llamada a `/userinfo`.
- **Modo "Rómpelo"**: login CSRF (`state` cambiado), `redirect_uri` no registrada, `code_verifier` incorrecto, token manipulado sin volver a firmar, y llamar a la API con el `id_token` o sin token.

## Simplificaciones (intencionadas)

- Un único usuario de prueba, sin contraseña: el foco es el protocolo.
- El código de autorización es un JWT firmado y sin estado (60 s). Un servidor real lo persiste y lo invalida al primer uso.
- Los tokens se guardan en `sessionStorage` para enseñarlos.

**No es un proveedor de identidad para producción.**

## Arquitectura

Un solo Worker (`src/worker.js`) sirve las rutas `/as/*` y la discovery; el resto lo sirven los estáticos de `public/`. Sin dependencias: solo Web Crypto.

```
navegador (SPA, public/app.js)
   │  1. GET /as/authorize ───────────►  Worker: pantalla de consentimiento
   │  2. ◄── 302 /?code=…&state=…
   │  3. POST /as/token (code + verifier) ─►  Worker: comprueba PKCE, firma tokens
   │  4. GET /as/jwks ────────────────►  clave pública para validar el id_token
   │  5. GET /as/userinfo (Bearer) ───►  Worker: valida el access_token
```

## Despliegue

1. Genera la clave de firma: `node scripts/generate-key.mjs`.
2. En Cloudflare, en el Worker `iam-lab`: **Ajustes → Variables y secretos → Añadir → Secreto**, nombre `PRIVATE_JWK`, valor: la línea generada.
3. Cada push a `main` se despliega con Workers Builds.

Sin el secreto, el Worker usa una clave efímera por instancia: sirve para probar, pero los tokens pueden fallar al validarse.

## Tests

```bash
node --test test/flow.test.mjs
```

Cubren el flujo completo y los ataques del modo "Rómpelo" contra el Worker, sin necesidad de Cloudflare.

---

Hecho por [spliter.dev](https://spliter.dev).
