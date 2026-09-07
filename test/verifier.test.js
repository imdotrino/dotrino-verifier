// Protocolo de verificación: armar prueba → publicar (simulado) → verificar → firmar
// atestación (tercero) → validar firma del verificador. Incluye casos de manipulación.
import { test } from 'node:test'
import assert from 'node:assert'
import { makeDeviceKey, signWithDevice } from '@dotrino/identity/capabilities'
import {
  makeProof, parseProof, verifyProof, signVerification, verifyVerification,
  proofUrls, normHandle, isSupportedService
} from '../src/index.js'

// Helper: una "identidad" (usuario o verificador) con su firma.
async function newIdentity () {
  const k = await makeDeviceKey({})
  const sign = (data) => signWithDevice({ privateJwk: k.privateJwk, data }).then((r) => r.signature)
  return { pubkey: k.publickey, privateJwk: k.privateJwk, sign }
}

test('flujo feliz: armar prueba → verificar → atestar (tercero) → validar', async () => {
  const user = await newIdentity()
  const verifier = await newIdentity()

  const { token } = await makeProof({ pubkey: user.pubkey, sign: user.sign, service: 'web', handle: 'alice.com' })
  // La página pública (con ruido alrededor de la prueba).
  const page = `# Mi sitio\nHola mundo\n${token}\nfooter`

  const vp = await verifyProof({ text: page, pubkey: user.pubkey, service: 'web', handle: 'alice.com' })
  assert.strictEqual(vp.ok, true, vp.reason)

  // El VERIFICADOR (otra identidad) firma la atestación op:'verify'.
  const att = await signVerification({ verifierKey: verifier.privateJwk, verifierPubkey: verifier.pubkey, sub: user.pubkey, service: 'web', handle: 'alice.com' })
  assert.strictEqual(att.op, 'verify')
  assert.strictEqual(att.iss, verifier.pubkey)   // emisor = verificador, no el usuario
  assert.strictEqual(att.sub, user.pubkey)
  assert.strictEqual(att.ch, 'web')
  assert.strictEqual(att.reveal, undefined, 'por defecto NO revela el dato')

  const vv = await verifyVerification(att)
  assert.strictEqual(vv.ok, true, vv.reason)
})

test('handle normalizado y URL derivada (liga URL↔handle)', async () => {
  assert.strictEqual(normHandle('web', 'HTTPS://Alice.COM/path'), 'alice.com')
  assert.strictEqual(normHandle('github', '@Foo'), 'foo')
  assert.deepStrictEqual(proofUrls('web', 'alice.com'), ['https://alice.com/.well-known/dotrino.txt'])
  assert.ok(proofUrls('github', 'foo')[0].includes('raw.githubusercontent.com/foo/foo/'))
  assert.strictEqual(isSupportedService('x'), false) // X aún no
})

test('rechaza prueba ausente / handle distinto / otra identidad / firma alterada', async () => {
  const user = await newIdentity()
  const other = await newIdentity()
  const { token } = await makeProof({ pubkey: user.pubkey, sign: user.sign, service: 'web', handle: 'alice.com' })

  assert.strictEqual((await verifyProof({ text: 'sin prueba', pubkey: user.pubkey, service: 'web', handle: 'alice.com' })).ok, false)
  // mismo token pero reclamando OTRO handle → no coincide
  assert.strictEqual((await verifyProof({ text: token, pubkey: user.pubkey, service: 'web', handle: 'bob.com' })).ok, false)
  // la prueba es del usuario, pero se verifica contra OTRA identidad → rechaza
  assert.strictEqual((await verifyProof({ text: token, pubkey: other.pubkey, service: 'web', handle: 'alice.com' })).ok, false)
  // token manipulado (cambiar un char del claim) → firma inválida o parseo roto
  const broken = token.replace('dotrino-verify:', 'dotrino-verify:AAAA')
  assert.strictEqual((await verifyProof({ text: broken, pubkey: user.pubkey, service: 'web', handle: 'alice.com' })).ok, false)
})

test('atestación con reveal (opt-in) expone solo el handle; manipularla la invalida', async () => {
  const user = await newIdentity()
  const verifier = await newIdentity()
  const att = await signVerification({ verifierKey: verifier.privateJwk, verifierPubkey: verifier.pubkey, sub: user.pubkey, service: 'web', handle: 'alice.com', reveal: true, proofUrl: 'https://alice.com/.well-known/dotrino.txt' })
  assert.strictEqual(att.reveal.handle, 'alice.com')
  assert.strictEqual(att.reveal.proofUrl, 'https://alice.com/.well-known/dotrino.txt')
  assert.strictEqual((await verifyVerification(att)).ok, true)

  // Si un atacante cambia el sujeto (robar el badge para otra identidad), la firma cae.
  const forged = { ...att, sub: (await newIdentity()).pubkey }
  assert.strictEqual((await verifyVerification(forged)).ok, false)
})

test('atestación expirada se rechaza', async () => {
  const user = await newIdentity()
  const verifier = await newIdentity()
  const att = await signVerification({ verifierKey: verifier.privateJwk, verifierPubkey: verifier.pubkey, sub: user.pubkey, service: 'web', handle: 'alice.com', ttlMs: -1000 })
  assert.strictEqual((await verifyVerification(att)).ok, false)
})

// ----- El directorio de una empresa: pertenencia, no control de un handle -----

test('una atestación de directorio dice a qué grupos perteneces, y para quién vale', async () => {
  const empresa = await makeDeviceKey({ label: 'servicio de la empresa' })
  const maria = await makeDeviceKey({ label: 'perfil de trabajo' })

  const att = await signVerification({
    verifierKey: empresa.privateJwk, verifierPubkey: empresa.publickey,
    sub: maria.publickey, service: 'directory', claim: 'member',
    aud: 'https://chat.empresa.com', ttlMs: 60 * 60 * 1000,
    claims: { upn: 'maria@empresa.com', displayName: 'María Ruiz', groups: ['Ingenieria', 'Todos'] }
  })

  assert.equal(att.ch, 'directory')
  assert.equal(att.claim, 'member', 'afirma pertenencia, no control')
  assert.deepEqual(att.claims.groups, ['Ingenieria', 'Todos'])

  const v = await verifyVerification(att, { audience: 'https://chat.empresa.com' })
  assert.equal(v.ok, true, v.reason)
})

test('la atestación de una aplicación no vale en otra', async () => {
  const empresa = await makeDeviceKey({ label: 'empresa' })
  const maria = await makeDeviceKey({ label: 'maria' })
  const att = await signVerification({
    verifierKey: empresa.privateJwk, verifierPubkey: empresa.publickey, sub: maria.publickey,
    service: 'directory', claim: 'member', aud: 'https://chat.empresa.com',
    claims: { upn: 'maria@empresa.com', groups: ['Todos'] }
  })
  const v = await verifyVerification(att, { audience: 'https://otra.empresa.com' })
  assert.equal(v.ok, false)
  assert.equal(v.reason, 'otro destinatario')
})

test('si esperas un destinatario, una atestación sin él NO vale', async () => {
  const empresa = await makeDeviceKey({ label: 'empresa' })
  const maria = await makeDeviceKey({ label: 'maria' })
  const att = await signVerification({
    verifierKey: empresa.privateJwk, verifierPubkey: empresa.publickey, sub: maria.publickey,
    service: 'directory', claim: 'member', claims: { upn: 'maria@empresa.com' }
  })
  assert.equal((await verifyVerification(att, { audience: 'https://chat.empresa.com' })).reason, 'sin destinatario')
  assert.equal((await verifyVerification(att)).ok, true, 'sin esperar destinatario, sigue valiendo')
})

test('tocar los grupos invalida la firma', async () => {
  const empresa = await makeDeviceKey({ label: 'empresa' })
  const maria = await makeDeviceKey({ label: 'maria' })
  const att = await signVerification({
    verifierKey: empresa.privateJwk, verifierPubkey: empresa.publickey, sub: maria.publickey,
    service: 'directory', claim: 'member', claims: { upn: 'maria@empresa.com', groups: ['Todos'] }
  })
  const falsa = { ...att, claims: { ...att.claims, groups: ['Todos', 'Administradores'] } }
  const v = await verifyVerification(falsa)
  assert.equal(v.ok, false)
  assert.match(v.reason, /firma/)
})
