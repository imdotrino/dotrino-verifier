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
- `signVerification({ verifierKey, verifierPubkey, sub, service, handle, reveal?, ttlMs?, proofUrl? })` → atestación `op:'verify'`
- `verifyVerification(att)` → `{ ok, reason? }`
- `proofUrls(service, handle)`, `normHandle(service, handle)`, `isSupportedService(service)`, `SERVICES`

Servicios v1: **`web`** (dominio, prueba en `/.well-known/dotrino.txt`) y **`github`** (README del
repo de perfil). X/LinkedIn requieren login/scraping → más adelante.

MIT.
