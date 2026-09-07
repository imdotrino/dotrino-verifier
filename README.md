# @dotrino/verifier

Protocolo de **verificación de identidad** de Dotrino: prueba pública bidireccional (estilo
Keybase) + atestación `op:'verify'` firmada por un **verificador-tercero federado**.

Principios (ver `dotrino-reputation/docs/federacion-confianza.md`):

- **Verificado ≠ revelar.** El badge prueba "esta identidad controla X"; el dato (el handle,
  el correo) **no se expone** salvo opt-in (`reveal`).
- **El verificador es un tercero que firma.** Un auto-badge no vale: otra identidad (un
  verificador) chequea la prueba pública y firma la atestación.
- **Cualquiera puede ser verificador** corriendo esta misma app; Dotrino corre su bot, sin
  privilegio. La confianza del badge sale del web-of-trust sobre el emisor (`aggregateTrust`
  de `@dotrino/reputation`).
- No reimplementa cripto: usa `@dotrino/identity/capabilities` (ECDSA P-256 +
  `canonicalStringify`), el mismo formato de firma que `@dotrino/reputation`.

## Flujo (redes / web, auto-verificable)

```js
import { makeProof, verifyProof, signVerification, verifyVerification, proofUrls } from '@dotrino/verifier'

// 1) El USUARIO arma la prueba con su vault y la publica en su cuenta/sitio público.
const { token, urls } = await makeProof({
  pubkey,                                   // JWK público del usuario
  sign: (d) => identity.signData(d).then(r => r.signature),
  service: 'web',                           // 'web' | 'github'
  handle: 'alice.com'
})
// → publica `token` en proofUrls('web','alice.com')[0]  (https://alice.com/.well-known/dotrino.txt)

// 2) El VERIFICADOR baja esa URL pública (Worker, por CORS), valida y firma la atestación.
const page = await fetchPublic(urls[0])
const vp = await verifyProof({ text: page, pubkey, service: 'web', handle: 'alice.com' })
if (vp.ok) {
  const att = await signVerification({
    verifierKey, verifierPubkey,            // identidad del verificador
    sub: pubkey, service: 'web', handle: 'alice.com'
    // reveal: true   ← opt-in; por defecto NO expone el handle
  })
  // → publicar `att` en reputation.dotrino.com (op:'verify')
}

// 3) El PERFIL valida la firma del verificador; el PESO lo da aggregateTrust(att.iss).
const ok = (await verifyVerification(att)).ok
```

## API

- `makeProof({ pubkey, sign, service, handle })` → `{ claim, token, urls, line }`
- `parseProof(text)` → `{ claim, sig } | null`
- `verifyProof({ text, pubkey, service, handle })` → `{ ok, reason?, claim? }`
- `signVerification({ verifierKey, verifierPubkey, sub, service, handle, reveal?, ttlMs?, proofUrl?, aud?, claim?, claims? })` → atestación `op:'verify'`
- `verifyVerification(att, { audience? })` → `{ ok, reason? }`
- `proofUrls(service, handle)`, `normHandle(service, handle)`, `isSupportedService(service)`, `SERVICES`

Servicios: **`web`** (dominio, prueba en `/.well-known/dotrino.txt`), **`github`** (README del
repo de perfil) y **`directory`** (el directorio de una empresa). X/LinkedIn requieren
login/scraping → más adelante.

### `directory` no funciona como los otros dos, y conviene ver por qué

En `web` y `github` la prueba es **pública**: cualquiera la baja y comprueba, y el
verificador solo mira. En `directory` no hay nada que bajar — quien comprueba es el propio
servicio de la empresa hablando con su Active Directory, y lo que firma es el resultado de
esa conversación. De ahí las tres diferencias: no tiene `urls`, su atestación dice
`claim: 'member'` (pertenencia) en vez de `controls`, y lleva `claims` con lo que la
aplicación necesita para decidir (`upn`, `groups`). Lo usa
[`dotrino-ad-integration`](https://github.com/imdotrino/dotrino-ad-integration).

### El destinatario (`aud`)

`signVerification({ aud })` marca **para quién** vale una atestación, y
`verifyVerification(att, { audience })` lo exige. Sin él, un respaldo firmado para el chat
de la empresa sirve igual ante cualquier otra aplicación que lo acepte — el mismo agujero
que se cerró en el resto del ecosistema. Y si esperas destinatario, una atestación que no
lo trae **no vale**: aceptarla es el agujero otra vez.

MIT.
