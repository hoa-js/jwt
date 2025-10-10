import { jwtVerify, createRemoteJWKSet, SignJWT, importSPKI, importPKCS8 } from 'jose'

/**
 * JWT middleware for Hoa
 *
 * Usage:
 *   app.use(jwt({ secret: 'shhhh', algorithms: ['HS256'] }))
 *
 * Attaches verified payload to ctx.state[key] (default: 'user').
 * Also sets ctx.state.jwt = { token, header, payload } for convenience.
 *
 * @typedef {import('hoa').HoaContext} HoaContext
 *
 * @typedef {Object} JWTOptions
 * @property {string | Uint8Array | CryptoKey | import('jose').KeyLike | ((token?: string) => string | Uint8Array | CryptoKey | import('jose').KeyLike | Promise<string | Uint8Array | CryptoKey | import('jose').KeyLike>)} [secret] - Secret or key material, or a function to resolve it dynamically by token
 * @property {string[]} [algorithms] - Allowed algorithms, default ['HS256']
 * @property {(ctx: HoaContext) => (string | null | undefined | Promise<string | null | undefined>)} [getToken] - Custom token extractor
 * @property {string} [cookie] - Cookie name to read token from if Authorization header is absent
 * @property {string} [key] - ctx.state key to store verified payload, default 'user'
 * @property {boolean} [credentialsRequired] - If true, missing token throws 401; default true
 * @property {boolean} [passthrough] - If true, do not throw on error; continue to next()
 * @property {(ctx: HoaContext, payload: any) => boolean | Promise<boolean>} [isRevoked] - Optional revocation check
 * @property {string | string[]} [issuer] - Expected issuer claim(s)
 * @property {string | string[]} [audience] - Expected audience claim(s)
 * @property {string} [subject] - Expected subject claim
 * @property {string | number} [clockTolerance] - Allowed clock skew
 * @property {string} [jwksUri] - Remote JWKS endpoint for asymmetric verification
 *
 * @param {JWTOptions} [options] - JWT verification options
 * @returns {(ctx: HoaContext, next: () => Promise<void>) => Promise<void>}
 */
export function jwt (options = {}) {
  const {
    secret,
    algorithms = ['HS256'],
    getToken,
    cookie,
    key = 'user',
    credentialsRequired = true,
    passthrough = false,
    isRevoked,
    issuer,
    audience,
    subject,
    clockTolerance,
    jwksUri
  } = options

  return async function jwtMiddleware (ctx, next) {
    try {
      // Extract token
      let token
      if (typeof getToken === 'function') {
        token = await getToken(ctx)
      }
      if (!token) {
        token = getBearerToken(ctx)
      }
      if (!token && cookie) {
        const cookies = parseCookie(ctx.req.get('Cookie') || '')
        token = cookies[cookie]
      }

      // Token missing
      if (!token) {
        if (credentialsRequired === false || passthrough) {
          return next()
        }
        const hdr = buildWwwAuthenticate('invalid_token', 'No authorization token was found')
        ctx.throw(401, 'Unauthorized', { headers: { 'WWW-Authenticate': hdr } })
      }

      let verified
      try {
        verified = await verifyJWT(token, { secret, algorithms, issuer, audience, subject, clockTolerance, jwksUri })
      } catch (err) {
        if (passthrough) {
          return next()
        }
        const hdr = buildWwwAuthenticate('invalid_token', err?.message || 'Invalid token')
        ctx.throw(401, 'Unauthorized', { headers: { 'WWW-Authenticate': hdr } })
      }

      const { payload, protectedHeader } = verified

      // Revocation check
      if (typeof isRevoked === 'function') {
        const revoked = await isRevoked(ctx, payload)
        if (revoked) {
          if (passthrough) return next()
          const hdr = buildWwwAuthenticate('invalid_token', 'Token has been revoked')
          ctx.throw(401, 'Unauthorized', { headers: { 'WWW-Authenticate': hdr } })
        }
      }

      // Attach to state
      ctx.state[key] = payload
      ctx.state.jwt = { token, header: protectedHeader, payload }

      await next()
    } catch (err) {
      if (passthrough) {
        return next()
      }
      throw err
    }
  }
}

/**
 * Parse cookies from a Cookie header string.
 * @param {string} str
 * @returns {Record<string,string>}
 */
function parseCookie (str) {
  const out = Object.create(null)
  if (!str) return out
  for (const part of str.split(';')) {
    const idx = part.indexOf('=')
    if (idx === -1) continue
    const k = part.slice(0, idx).trim()
    let v = part.slice(idx + 1).trim()
    // Remove quotes if present
    if (v.startsWith('"') && v.endsWith('"')) {
      v = v.slice(1, -1)
    }
    try {
      v = decodeURIComponent(v)
    } catch (e) {
      // If decoding fails, use the raw value
    }
    if (k) out[k] = v
  }
  return out
}

/**
 * Extract bearer token from Authorization header.
 * @param {HoaContext} ctx
 * @returns {string|null}
 */
function getBearerToken (ctx) {
  const auth = ctx.req.get('Authorization') || ''
  if (!auth) return null
  const [scheme, ...rest] = auth.split(' ')
  if (!scheme || scheme.toLowerCase() !== 'bearer') return null
  const token = rest.join(' ').trim()
  return token || null
}

/**
 * Normalize secret input for jose based on algorithm.
 * - HS* with string secret: encodes to Uint8Array via TextEncoder
 * - RS* with string PEM: imports to KeyLike (SPKI for public keys, PKCS#8 for private keys);
 *   if import fails, falls back to returning the original string
 * - Other inputs are returned as-is
 * @param {string | Uint8Array | CryptoKey | import('jose').KeyLike} secret
 * @param {string[]} algorithms - Allowed algorithms (e.g. ['HS256'] or ['RS256'])
 * @returns {Promise<string | Uint8Array | CryptoKey | import('jose').KeyLike>}
 */
async function normalizeSecret (secret, algorithms) {
  const usesHS = algorithms.some(a => a.startsWith('HS'))
  const usesRS = algorithms.some(a => a.startsWith('RS'))
  if (typeof secret === 'string') {
    if (usesHS) {
      return new TextEncoder().encode(secret)
    }
    if (usesRS) {
      const alg = algorithms.find(a => a.startsWith('RS'))
      const s = secret.trim()
      // Detect PEM types and import to KeyLike
      if (s.includes('BEGIN PUBLIC KEY') || s.includes('BEGIN RSA PUBLIC KEY')) {
        try {
          return await importSPKI(s, alg)
        } catch {
          // fall through to return original string if import fails
        }
      }
      if (s.includes('BEGIN PRIVATE KEY') || s.includes('BEGIN RSA PRIVATE KEY')) {
        try {
          return await importPKCS8(s, alg)
        } catch {
          // fall through to return original string if import fails
        }
      }
    }
  }
  return secret
}

/**
 * Build WWW-Authenticate header for 401 responses.
 * @param {string} code
 * @param {string} description
 * @returns {string}
 */
function buildWwwAuthenticate (code, description) {
  // Following RFC 6750 format
  const params = [
    'Bearer realm="hoa"',
    `error="${code}"`,
    `error_description="${description.replace(/"/g, '\\"')}"`
  ].filter(Boolean)
  return params.join(', ')
}

/**
 * Verify a JWT using jose.
 * Supports static secret, dynamic secret via token, and remote JWKS.
 * @param {string} token
 * @param {{ secret?: string | Uint8Array | CryptoKey | import('jose').KeyLike | ((token?: string) => string | Uint8Array | CryptoKey | import('jose').KeyLike | Promise<string | Uint8Array | CryptoKey | import('jose').KeyLike>)}, algorithms?: string[], issuer?: string | string[], audience?: string | string[], subject?: string, clockTolerance?: string | number, jwksUri?: string }} [options]
 * @returns {Promise<{ payload: import('jose').JWTPayload, protectedHeader: import('jose').JWSHeaderParameters }>}
 */
export async function verifyJWT (token, options = {}) {
  const { secret, algorithms = ['HS256'], issuer, audience, subject, clockTolerance, jwksUri } = options

  // Resolve verification key or JWKS
  let keyOrSecret
  if (jwksUri) {
    keyOrSecret = createRemoteJWKSet(new URL(jwksUri))
  } else if (typeof secret === 'function') {
    keyOrSecret = await secret(token)
    keyOrSecret = await normalizeSecret(keyOrSecret, algorithms)
  } else if (secret) {
    keyOrSecret = await normalizeSecret(secret, algorithms)
  } else {
    throw new Error('Verification secret is not configured')
  }

  const verifyOptions = { issuer, audience, subject, clockTolerance, algorithms }
  return jwtVerify(token, keyOrSecret, verifyOptions)
}

/**
 * Convenience helper to generate a JWT using jose SignJWT.
 * @param {Record<string, any>} payload
 * @param {string | Uint8Array | CryptoKey | import('jose').KeyLike} secret
 * @param {{ algorithm?: string, issuer?: string, audience?: string, subject?: string, expiresIn?: string | number, header?: Record<string, any> }} [options]
 * @returns {Promise<string>}
 */
export async function signJWT (payload, secret, options = {}) {
  const { algorithm = 'HS256', issuer, audience, subject, expiresIn, header } = options

  const encSecret = await normalizeSecret(secret, [algorithm])
  const signer = new SignJWT(payload)

  signer.setIssuedAt()
  if (issuer) signer.setIssuer(issuer)
  if (audience) signer.setAudience(audience)
  if (subject) signer.setSubject(subject)
  if (expiresIn) signer.setExpirationTime(expiresIn)
  const protectedHeader = { alg: algorithm, ...(header || {}) }
  signer.setProtectedHeader(protectedHeader)

  return signer.sign(encSecret)
}

export default jwt
