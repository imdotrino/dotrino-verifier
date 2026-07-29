/**
 * @dotrino/verifier — protocolo de verificación de identidad de Dotrino.
 *
 * Modelo (ver dotrino-reputation/docs/federacion-confianza.md):
 *  - **Verificado ≠ revelar.** El badge prueba "esta identidad controla X"; el dato (handle)
 *    NO se expone salvo opt-in (`reveal`).
 *  - **El verificador es un tercero que FIRMA.** No es el usuario quien se auto-verifica: un
 *    verificador (otra identidad) chequea la prueba pública y firma una atestación `op:'verify'`.
 *  - **Cualquiera puede ser verificador** (corre esta misma app); Dotrino corre su bot, sin
 *    privilegio. La confianza del badge sale del web-of-trust sobre el `iss` (`aggregateTrust`).
 *
 * Flujo (redes/web, auto-verificable estilo Keybase, BIDIRECCIONAL):
 *  1. El usuario arma una PRUEBA firmada con su vault: `makeProof({ pubkey, sign, service, handle })`.
 *  2. La publica en su cuenta/sitio PÚBLICO, en una URL que SOLO el dueño del handle controla
 *     (`proofUrls(service, handle)` → p. ej. `https://<dominio>/.well-known/dotrino.txt`).
 *  3. El verificador baja esa URL (un Worker, porque el navegador no puede por CORS), valida la
 *     prueba (`verifyProof`) y, si pasa, firma la atestación (`signVerification`).
 *  4. El perfil valida la firma del verificador (`verifyVerification`) y pinta el badge; el PESO
 *     lo da `aggregateTrust(iss)` en `@dotrino/reputation`.
 *
 * No reimplementa cripto: usa `@dotrino/identity/capabilities` (ECDSA P-256 + canonicalStringify),
 * el MISMO formato de firma que `@dotrino/reputation` → la atestación entra por su path existente.
 */
import { signWithDevice, verifyDeviceSig, pubkeyId } from '@dotrino/identity/capabilities'

const PROOF_TAG = 'dotrino-verify:'
const enc = (s) => new TextEncoder().encode(s)

// ----- base64url sobre UTF-8 (browser + node) -----
function b64url (bytes) {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
function unb64url (s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='
  const bin = atob(s); const a = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i)
  return a
}
const encJson = (obj) => b64url(enc(JSON.stringify(obj)))
const decJson = (s) => JSON.parse(new TextDecoder().decode(unb64url(s)))

// ----- servicios soportados (la URL de prueba se DERIVA del handle → liga URL↔handle) -----
// Solo servicios donde la URL de la prueba la controla únicamente el dueño del handle. X/LinkedIn
// (scraping/ToS/login) quedan para después; aquí: web (dominio) y GitHub (repo perfil del usuario).
export const SERVICES = {
  web: {
    label: 'Sitio web',
    norm: (h) => String(h || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, ''),
    urls: (h) => [`https://${h}/.well-known/dotrino.txt`]
  },
  github: {
    label: 'GitHub',
    norm: (h) => String(h || '').trim().toLowerCase().replace(/^@/, '').replace(/^https?:\/\/github\.com\//, '').replace(/\/.*$/, ''),
    // La prueba va en el README del repo de perfil del usuario (github.com/<h>/<h>), que solo <h> controla.
    urls: (h) => [
      `https://raw.githubusercontent.com/${h}/${h}/HEAD/README.md`,
      `https://raw.githubusercontent.com/${h}/${h}/main/README.md`,
      `https://raw.githubusercontent.com/${h}/${h}/master/README.md`
    ]
  }
}

export function isSupportedService (service) { return !!SERVICES[service] }
export function normHandle (service, handle) {
  const s = SERVICES[service]
  return s ? s.norm(handle) : String(handle || '').trim().toLowerCase()
}
/** URLs públicas (derivadas del handle) donde el verificador buscará la prueba. */
export function proofUrls (service, handle) {
  const s = SERVICES[service]
  return s ? s.urls(s.norm(handle)) : []
}

/**
 * Arma la prueba que el usuario PUBLICA. `sign(dataObj)` debe firmar `canonicalStringify(dataObj)`
 * con la identidad del usuario y devolver la firma base64 (p. ej. `identity.signData(d).signature`
 * en el browser, o `signWithDevice` en node). `pubkey` = JWK string de la identidad del usuario.
 * @returns {Promise<{ claim, token, urls, line }>}  `token`/`line` es lo que se publica.
 */
export async function makeProof ({ pubkey, sign, service, handle }) {
  if (!SERVICES[service]) throw new Error('servicio no soportado: ' + service)
  if (typeof sign !== 'function') throw new Error('falta sign()')
  const claim = { v: 1, sub: await pubkeyId(pubkey), svc: service, handle: normHandle(service, handle), ts: Date.now() }
  const signature = await sign(claim)
  if (typeof signature !== 'string') throw new Error('sign() debe devolver la firma base64')
  const token = PROOF_TAG + encJson(claim) + '.' + signature
  return { claim, token, urls: proofUrls(service, handle), line: token }
}

/** Extrae { claim, sig } de un texto público (la página bajada). Devuelve null si no hay prueba. */
export function parseProof (text) {
  if (typeof text !== 'string') return null
  const m = text.match(/dotrino-verify:([A-Za-z0-9\-_]+)\.([A-Za-z0-9+/=]+)/)
  if (!m) return null
  try { return { claim: decJson(m[1]), sig: m[2] } } catch { return null }
}

/**
 * Valida la prueba bajada (`text`) contra la identidad y el handle reclamados. NO baja la URL
 * (eso lo hace el verificador/Worker con `proofUrls`); acá solo se valida el contenido + la firma.
 * @returns {Promise<{ ok:boolean, reason?:string, claim?:object }>}
 */
export async function verifyProof ({ text, pubkey, service, handle }) {
  const p = parseProof(text)
  if (!p) return { ok: false, reason: 'no se encontró la prueba en la página pública' }
  const { claim, sig } = p
  if (claim.svc !== service) return { ok: false, reason: 'la prueba es de otro servicio' }
  if (normHandle(service, claim.handle) !== normHandle(service, handle)) return { ok: false, reason: 'el handle no coincide' }
  if (claim.sub !== await pubkeyId(pubkey)) return { ok: false, reason: 'la prueba no es de esta identidad' }
  const ok = await verifyDeviceSig({ publickey: pubkey, data: claim, signature: sig })
  if (!ok) return { ok: false, reason: 'firma de la prueba inválida' }
  return { ok: true, claim }
}

/**
 * El VERIFICADOR firma la atestación `op:'verify'`. `verifierKey` = privateJwk del verificador;
 * `verifierPubkey` = su JWK público (= `iss`). `sub` = JWK público del usuario verificado.
 * `reveal:true` (opt-in) adjunta el handle público; por defecto NO se expone nada.
 * El objeto resultante entra tal cual en `@dotrino/reputation` (mismo formato de firma).
 */
export async function signVerification ({ verifierKey, verifierPubkey, sub, service, handle, reveal = false, ttlMs = null, proofUrl = null }) {
  if (!SERVICES[service]) throw new Error('servicio no soportado: ' + service)
  const att = { op: 'verify', iss: verifierPubkey, sub, ch: service, claim: 'controls', ts: Date.now() }
  if (ttlMs) att.exp = att.ts + ttlMs
  if (reveal) { att.reveal = { handle: normHandle(service, handle) }; if (proofUrl) att.reveal.proofUrl = proofUrl }
  const { signature } = await signWithDevice({ privateJwk: verifierKey, data: att })
  return { ...att, sig: signature }
}

/**
 * Valida que una atestación `op:'verify'` está bien firmada por su `iss` (el verificador). El
 * PESO/confianza NO se decide aquí: lo da `aggregateTrust(iss)` (la reputación del verificador).
 * @returns {Promise<{ ok:boolean, reason?:string }>}
 */
export async function verifyVerification (att) {
  if (!att || att.op !== 'verify' || typeof att.iss !== 'string' || typeof att.sub !== 'string' || typeof att.sig !== 'string') {
    return { ok: false, reason: 'forma inválida' }
  }
  if (att.exp && Date.now() > att.exp) return { ok: false, reason: 'expirada' }
  const { sig, ...body } = att
  const ok = await verifyDeviceSig({ publickey: att.iss, data: body, signature: sig })
  return ok ? { ok: true } : { ok: false, reason: 'firma del verificador inválida' }
}
