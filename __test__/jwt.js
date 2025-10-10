import Hoa from 'hoa'
import jwtDefault, { jwt, signJWT, verifyJWT } from '../src/jwt.js'
import { generateKeyPair, exportJWK, exportSPKI, exportPKCS8 } from 'jose'
import http from 'node:http'

const SECRET = 'shhhh'

const createApp = (middleware, handler = (ctx) => { ctx.res.body = 'OK' }) => {
  const app = new Hoa()
  app.use(middleware)
  app.use(handler)
  return app
}

const fetchApp = (app, url = 'http://localhost/', options = {}) => {
  return app.fetch(new Request(url, options))
}

const createJWKSServer = async (publicKey) => {
  const pubJwk = await exportJWK(publicKey)
  pubJwk.kid = 'remote-kid'

  const server = http.createServer((req, res) => {
    if (req.url === '/jwks') {
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ keys: [pubJwk] }))
    } else {
      res.statusCode = 404
      res.end('not found')
    }
  })

  await new Promise(resolve => server.listen(0, resolve))
  const { port } = server.address()
  return { server, jwksUri: `http://127.0.0.1:${port}/jwks` }
}

const closeServer = (server) => new Promise(resolve => server.close(resolve))

describe('JWT Middleware - Core Functionality', () => {
  test('valid token attaches payload to ctx.state[key]', async () => {
    const token = await signJWT({ name: 'alice' }, SECRET, { algorithm: 'HS256' })
    const app = createApp(
      jwt({ secret: SECRET, algorithms: ['HS256'] }),
      (ctx) => { ctx.res.body = `Hello, ${ctx.state.user.name}!` }
    )
    const res = await fetchApp(app, 'http://localhost/', {
      headers: { Authorization: `Bearer ${token}` }
    })

    expect(res.status).toBe(200)
    expect(await res.text()).toBe('Hello, alice!')
  })

  test('custom state key option', async () => {
    const token = await signJWT({ name: 'dave' }, SECRET, { algorithm: 'HS256' })
    const app = createApp(
      jwt({ secret: SECRET, algorithms: ['HS256'], key: 'account' }),
      (ctx) => { ctx.res.body = `Hello, ${ctx.state.account.name}!` }
    )
    const res = await fetchApp(app, 'http://localhost/', {
      headers: { Authorization: `Bearer ${token}` }
    })

    expect(res.status).toBe(200)
    expect(await res.text()).toBe('Hello, dave!')
  })

  test('default and named exports both work', async () => {
    const token = await signJWT({ name: 'eve' }, SECRET)

    // Named export
    let app = createApp(
      jwt({ secret: SECRET, algorithms: ['HS256'] }),
      (ctx) => { ctx.res.body = `Hello, ${ctx.state.user.name}!` }
    )
    let res = await fetchApp(app, 'http://localhost/', { headers: { Authorization: `Bearer ${token}` } })
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('Hello, eve!')

    // Default export
    app = createApp(
      jwtDefault({ secret: SECRET, algorithms: ['HS256'] }),
      (ctx) => { ctx.res.body = `U:${ctx.state.user.name}` }
    )
    res = await fetchApp(app, 'http://localhost/', { headers: { Authorization: `Bearer ${token}` } })
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('U:eve')
  })
})

describe('JWT Middleware - Authentication & Authorization', () => {
  test('missing token returns 401 (default credentialsRequired)', async () => {
    const app = createApp(jwt({ secret: SECRET }))
    const res = await fetchApp(app)

    expect(res.status).toBe(401)
    expect(await res.text()).toBe('Unauthorized')
    expect(res.headers.get('WWW-Authenticate')).toContain('Bearer')
    expect(res.headers.get('WWW-Authenticate')).toContain('No authorization token was found')
  })

  test('invalid token returns 401', async () => {
    const app = createApp(jwt({ secret: SECRET }))
    const res = await fetchApp(app, 'http://localhost/', {
      headers: { Authorization: 'Bearer not-a-token' }
    })

    expect(res.status).toBe(401)
    expect(await res.text()).toBe('Unauthorized')
    expect(res.headers.get('WWW-Authenticate')).toContain('invalid_token')
  })

  test('credentialsRequired=false allows request without token', async () => {
    const app = createApp(jwt({ secret: SECRET, credentialsRequired: false }))
    const res = await fetchApp(app)

    expect(res.status).toBe(200)
    expect(await res.text()).toBe('OK')
  })

  test('passthrough=true allows requests without token or with invalid token', async () => {
    const app = createApp(jwt({ secret: SECRET, passthrough: true }))

    // No token
    let res = await fetchApp(app)
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('OK')

    // Invalid token
    res = await fetchApp(app, 'http://localhost/', {
      headers: { Authorization: 'Bearer not-a-token' }
    })
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('OK')
  })

  test('passthrough=true does not swallow downstream errors', async () => {
    const token = await signJWT({ x: 1 }, SECRET, { algorithm: 'HS256' })
    const app = createApp(
      jwt({ secret: SECRET, algorithms: ['HS256'], passthrough: true }),
      async () => { throw new Error('boom') }
    )
    const res = await fetchApp(app, 'http://localhost/', {
      headers: { Authorization: `Bearer ${token}` }
    })

    expect(res.status).toBe(500)
  })

  test('Authorization header edge cases', async () => {
    const app = createApp(jwt({ secret: SECRET }))

    // Test empty scheme (just spaces)
    let res = await fetchApp(app, 'http://localhost/', {
      headers: { Authorization: '   ' }
    })
    expect(res.status).toBe(401)

    // Test Bearer with only spaces after it (empty token)
    res = await fetchApp(app, 'http://localhost/', {
      headers: { Authorization: 'Bearer   ' }
    })
    expect(res.status).toBe(401)

    // Test Authorization header starting with space (empty scheme)
    res = await fetchApp(app, 'http://localhost/', {
      headers: { Authorization: ' token' }
    })
    expect(res.status).toBe(401)
  })

  test('custom getToken is used before header/cookie', async () => {
    const token = await signJWT({ name: 'bob' }, SECRET, { algorithm: 'HS256' })
    const app = createApp(
      jwt({ secret: SECRET, algorithms: ['HS256'], getToken: async () => token }),
      (ctx) => { ctx.res.body = `Hello, ${ctx.state.user.name}!` }
    )
    const res = await fetchApp(app, 'http://localhost/', {
      headers: { Authorization: 'Basic abc' }
    })

    expect(res.status).toBe(200)
    expect(await res.text()).toBe('Hello, bob!')
  })

  test('cookie token with quotes and with a bad cookie part decode', async () => {
    const token = await signJWT({ role: 'admin' }, SECRET, { algorithm: 'HS256' })
    const app = createApp(
      jwt({ secret: SECRET, algorithms: ['HS256'], cookie: 'auth' }),
      (ctx) => { ctx.res.body = `Role: ${ctx.state.user.role}` }
    )
    // Include a bad cookie segment to trigger decodeURIComponent failure path
    const res = await fetchApp(app, 'http://localhost/', {
      headers: { Cookie: `bad=%E0%A4%A; auth="${token}"` }
    })

    expect(res.status).toBe(200)
    expect(await res.text()).toBe('Role: admin')
  })

  test('isRevoked returns true -> 401 with revocation message', async () => {
    const token = await signJWT({ name: 'zoe' }, SECRET, { algorithm: 'HS256' })
    const app = createApp(
      jwt({ secret: SECRET, algorithms: ['HS256'], isRevoked: async () => true }),
      (ctx) => { ctx.res.body = 'SHOULD NOT REACH' }
    )
    const res = await fetchApp(app, 'http://localhost/', {
      headers: { Authorization: `Bearer ${token}` }
    })

    expect(res.status).toBe(401)
    const hdr = res.headers.get('WWW-Authenticate') || ''
    expect(hdr).toContain('Token has been revoked')
  })

  // parseCookie: decodeURIComponent failure should fall back to raw value
  // Provide invalid percent-encoding in cookie value
  // This ensures catch branch executes
  test('cookie parser decode failure falls back to raw value', async () => {
    const app = createApp(
      jwt({ secret: SECRET, algorithms: ['HS256'], cookie: 'auth' })
    )
    const res = await fetchApp(app, 'http://localhost/', {
      headers: { Cookie: 'auth=%E0%A4%A' }
    })
    expect(res.status).toBe(401)
    expect(await res.text()).toBe('Unauthorized')
    expect(res.headers.get('WWW-Authenticate')).toContain('invalid_token')
  })

  test('isRevoked returns true with passthrough=true continues', async () => {
    const token = await signJWT({ name: 'carol' }, SECRET, { algorithm: 'HS256' })
    const app = createApp(jwt({
      secret: SECRET,
      algorithms: ['HS256'],
      passthrough: true,
      isRevoked: async () => true
    }))
    const res = await fetchApp(app, 'http://localhost/', {
      headers: { Authorization: `Bearer ${token}` }
    })

    expect(res.status).toBe(200)
    expect(await res.text()).toBe('OK')
  })

  test('passthrough=true handles downstream errors without swallowing them', async () => {
    const token = await signJWT({ x: 1 }, SECRET, { algorithm: 'HS256' })
    const app = createApp(
      jwt({ secret: SECRET, algorithms: ['HS256'], passthrough: true }),
      async () => { throw new Error('boom') }
    )
    const res = await fetchApp(app, 'http://localhost/', {
      headers: { Authorization: `Bearer ${token}` }
    })

    expect(res.status).toBe(500)
  })

  test('claims mismatch (issuer/audience/subject) -> 401', async () => {
    const cases = [
      { name: 'issuer', signOpts: { issuer: 'app-a' }, verifyOpts: { issuer: 'app-b' } },
      { name: 'audience', signOpts: { audience: 'aud-a' }, verifyOpts: { audience: 'aud-b' } },
      { name: 'subject', signOpts: { subject: 'sub-a' }, verifyOpts: { subject: 'sub-b' } }
    ]

    for (const c of cases) {
      const token = await signJWT({}, SECRET, { algorithm: 'HS256', ...c.signOpts })
      const app = createApp(jwt({ secret: SECRET, algorithms: ['HS256'], ...c.verifyOpts }))
      const res = await fetchApp(app, 'http://localhost/', {
        headers: { Authorization: `Bearer ${token}` }
      })

      expect(res.status).toBe(401)
      expect(await res.text()).toBe('Unauthorized')
    }
  })

  test('clockTolerance allows expired token temporarily', async () => {
    const token = await signJWT({}, SECRET, { algorithm: 'HS256', expiresIn: '0s' })
    const app = createApp(jwt({ secret: SECRET, algorithms: ['HS256'], clockTolerance: '2s' }))
    const res = await fetchApp(app, 'http://localhost/', {
      headers: { Authorization: `Bearer ${token}` }
    })

    expect(res.status).toBe(200)
    expect(await res.text()).toBe('OK')
  })

  test('invalid token with passthrough=false -> 401', async () => {
    const app = createApp(jwt({ secret: SECRET }))
    const res = await fetchApp(app, 'http://localhost/', {
      headers: { Authorization: 'Bearer not-a-token' }
    })

    expect(res.status).toBe(401)
    expect(await res.text()).toBe('Unauthorized')
    expect(res.headers.get('WWW-Authenticate')).toContain('invalid_token')
  })

  test('custom state key option attaches to ctx.state[key]', async () => {
    const token = await signJWT({ name: 'dave' }, SECRET, { algorithm: 'HS256' })
    const app = createApp(
      jwt({ secret: SECRET, algorithms: ['HS256'], key: 'account' }),
      (ctx) => { ctx.res.body = `Hello, ${ctx.state.account.name}!` }
    )
    const res = await fetchApp(app, 'http://localhost/', {
      headers: { Authorization: `Bearer ${token}` }
    })

    expect(res.status).toBe(200)
    expect(await res.text()).toBe('Hello, dave!')
  })

  test('verifyJWT with dynamic secret function', async () => {
    const token = await signJWT({ uid: 1 }, SECRET, { algorithm: 'HS256' })
    const { payload, protectedHeader } = await verifyJWT(token, {
      secret: async () => SECRET,
      algorithms: ['HS256']
    })

    expect(payload.uid).toBe(1)
    expect(protectedHeader.alg).toBe('HS256')
  })

  test('verifyJWT throws when secret not configured', async () => {
    await expect(verifyJWT('abc')).rejects.toThrow('Verification secret is not configured')
  })

  test('verifyJWT algorithms mismatch -> throws', async () => {
    const token = await signJWT({}, SECRET, { algorithm: 'HS256' })
    await expect(verifyJWT(token, { secret: SECRET, algorithms: ['HS512'] })).rejects.toThrow()
  })

  test('signJWT supports RS256 with KeyLike and header merging', async () => {
    const { privateKey, publicKey } = await generateKeyPair('RS256')
    const token = await signJWT({ uid: 2 }, privateKey, { algorithm: 'RS256', header: { kid: 'k1' } })
    const { payload, protectedHeader } = await verifyJWT(token, { secret: publicKey, algorithms: ['RS256'] })
    expect(payload.uid).toBe(2)
    expect(protectedHeader.alg).toBe('RS256')
    expect(protectedHeader.kid).toBe('k1')
  })

  test('jwksUri remote verification (RS256)', async () => {
    const { privateKey, publicKey } = await generateKeyPair('RS256')
    const { server, jwksUri } = await createJWKSServer(publicKey)

    const token = await signJWT({ uid: 3 }, privateKey, {
      algorithm: 'RS256',
      header: { kid: 'remote-kid' }
    })
    const app = createApp(
      jwt({ jwksUri, algorithms: ['RS256'] }),
      (ctx) => { ctx.res.body = `ID:${ctx.state.user.uid}` }
    )
    const res = await fetchApp(app, 'http://localhost/', {
      headers: { Authorization: `Bearer ${token}` }
    })

    expect(res.status).toBe(200)
    expect(await res.text()).toBe('ID:3')

    await closeServer(server)
  })
})

describe('JWT Middleware - WWW-Authenticate Header', () => {
  test('WWW-Authenticate error_description: fallback and escaping', async () => {
    // Fallback when non-Error is thrown (no message) -> uses "Invalid token"
    // eslint-disable-next-line
    let app = createApp(jwt({ secret: () => { throw 'bar' }, algorithms: ['HS256'] }))
    let res = await fetchApp(app, 'http://localhost/', { headers: { Authorization: 'Bearer whatever' } })
    let hdr = res.headers.get('WWW-Authenticate') || ''
    expect(res.status).toBe(401)
    expect(hdr).toContain('error_description="Invalid token"')

    // Escapes quotes in error message
    app = createApp(jwt({ secret: () => { throw new Error('bad "token"') }, algorithms: ['HS256'] }))
    res = await fetchApp(app, 'http://localhost/', { headers: { Authorization: 'Bearer whatever' } })
    hdr = res.headers.get('WWW-Authenticate') || ''
    expect(res.status).toBe(401)
    expect(hdr).toContain('error_description="bad \\"token\\""')
  })

  test('verifyJWT supports Uint8Array secret for HS256', async () => {
    const token = await signJWT({ z: 9 }, SECRET, { algorithm: 'HS256' })
    const secretBytes = new TextEncoder().encode(SECRET)
    const app = createApp(
      jwt({ secret: secretBytes, algorithms: ['HS256'] }),
      (ctx) => { ctx.res.body = `Z:${ctx.state.user.z}` }
    )
    const res = await fetchApp(app, 'http://localhost/', {
      headers: { Authorization: `Bearer ${token}` }
    })

    expect(res.status).toBe(200)
    expect(await res.text()).toBe('Z:9')
  })

  test('cookie parser continues on segments without equals and decodes percent-encoded token', async () => {
    const token = await signJWT({ a: 1 }, SECRET, { algorithm: 'HS256' })
    const encoded = encodeURIComponent(token)
    const app = createApp(
      jwt({ secret: SECRET, algorithms: ['HS256'], cookie: 'auth' }),
      (ctx) => { ctx.res.body = `A:${ctx.state.user.a}` }
    )
    const res = await fetchApp(app, 'http://localhost/', {
      headers: { Cookie: `foo; auth=${encoded}` }
    })

    expect(res.status).toBe(200)
    expect(await res.text()).toBe('A:1')
  })

  test('verifyJWT with RS256 algorithms and string secret covers non-HS branch', async () => {
    await expect(verifyJWT('not.a.jwt', { secret: SECRET, algorithms: ['RS256'] })).rejects.toThrow()
  })

  test('normalizeSecret with non-HS non-RS algorithms and string secret returns original', async () => {
    // ES256 is neither HS* nor RS*, so normalizeSecret should return the original string
    await expect(verifyJWT('not.a.jwt', { secret: SECRET, algorithms: ['ES256'] })).rejects.toThrow()
  })

  test('isRevoked returns false -> proceed normally', async () => {
    const token = await signJWT({ name: 'frank' }, SECRET, { algorithm: 'HS256' })
    const app = createApp(
      jwt({ secret: SECRET, algorithms: ['HS256'], isRevoked: async () => false }),
      (ctx) => { ctx.res.body = `Hi, ${ctx.state.user.name}` }
    )
    const res = await fetchApp(app, 'http://localhost/', {
      headers: { Authorization: `Bearer ${token}` }
    })

    expect(res.status).toBe(200)
    expect(await res.text()).toBe('Hi, frank')
  })

  test('jwt default options (no arguments) -> 401 on missing token', async () => {
    const app = createApp(jwt())
    const res = await fetchApp(app)
    const hdr = res.headers.get('WWW-Authenticate') || ''

    expect(res.status).toBe(401)
    expect(hdr).toContain('No authorization token was found')
  })

  test('cookie option present but no Cookie header -> 401 (parses empty string)', async () => {
    const app = createApp(jwt({ secret: SECRET, algorithms: ['HS256'], cookie: 'auth' }))
    const res = await fetchApp(app) // no Cookie, no Authorization

    expect(res.status).toBe(401)
    expect(await res.text()).toBe('Unauthorized')
    expect(res.headers.get('WWW-Authenticate')).toContain('No authorization token was found')
  })

  test('cookie header includes empty key segment (=foo) and valid auth token', async () => {
    const token = await signJWT({ name: 'bob' }, SECRET, { algorithm: 'HS256' })
    const app = createApp(
      jwt({ secret: SECRET, algorithms: ['HS256'], cookie: 'auth' }),
      (ctx) => { ctx.res.body = `Hello, ${ctx.state.user.name}` }
    )
    const res = await fetchApp(app, 'http://localhost/', {
      headers: { Cookie: `=foo; auth="${token}"` }
    })

    expect(res.status).toBe(200)
    expect(await res.text()).toBe('Hello, bob')
  })

  test('normalizeSecret supports RS256 PEM strings for sign and verify', async () => {
    const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true })
    const spki = await exportSPKI(publicKey)
    const pkcs8 = await exportPKCS8(privateKey)

    const token = await signJWT({ x: 42 }, pkcs8, { algorithm: 'RS256' })
    const { payload } = await verifyJWT(token, { secret: spki, algorithms: ['RS256'] })
    expect(payload.x).toBe(42)
  })

  // RS256: invalid PEM should trigger import failure and fallback to original string
  // SPKI path (public key)
  test('normalizeSecret RS256 fallback on invalid SPKI PEM', async () => {
    const invalidSpki = '-----BEGIN RSA PUBLIC KEY-----\ninvalid\n-----END RSA PUBLIC KEY-----'
    await expect(verifyJWT('not.a.jwt', { secret: invalidSpki, algorithms: ['RS256'] })).rejects.toThrow()
  })

  // PKCS#8 path (private key)
  test('normalizeSecret RS256 fallback on invalid PKCS#8 PEM', async () => {
    const invalidPkcs8 = '-----BEGIN RSA PRIVATE KEY-----\ninvalid\n-----END RSA PRIVATE KEY-----'
    await expect(signJWT({ y: 1 }, invalidPkcs8, { algorithm: 'RS256' })).rejects.toThrow()
  })

  test('buildWwwAuthenticate without description', async () => {
    const app = createApp(jwt({ secret: SECRET }))
    // Trigger error without custom message by using empty Authorization header
    const res = await fetchApp(app, 'http://localhost/', {
      headers: { Authorization: '' }
    })

    expect(res.status).toBe(401)
    const hdr = res.headers.get('WWW-Authenticate') || ''
    expect(hdr).toContain('Bearer realm="hoa"')
    expect(hdr).toContain('error="invalid_token"')
  })

  test('error without message property triggers fallback in buildWwwAuthenticate', async () => {
    // Create a secret function that throws an error without a message
    const app = createApp(jwt({
      secret: () => {
        const err = new Error()
        err.message = '' // Empty message
        throw err
      },
      algorithms: ['HS256']
    }))

    const res = await fetchApp(app, 'http://localhost/', {
      headers: { Authorization: 'Bearer some-token' }
    })

    expect(res.status).toBe(401)
    const hdr = res.headers.get('WWW-Authenticate') || ''
    // Should use fallback 'Invalid token' when err.message is empty
    expect(hdr).toContain('error_description="Invalid token"')
  })
})
