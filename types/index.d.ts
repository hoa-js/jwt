import type { HoaContext, HoaMiddleware } from 'hoa'
import type { KeyLike, JWTPayload, JWSHeaderParameters } from 'jose'

export type JWTGetToken = (ctx: HoaContext) => string | null | undefined | Promise<string | null | undefined>

export interface JWTOptions {
  secret?:
    | string
    | Uint8Array
    | CryptoKey
    | KeyLike
    | ((token?: string) => string | Uint8Array | CryptoKey | KeyLike | Promise<string | Uint8Array | CryptoKey | KeyLike>)
  algorithms?: string[]
  getToken?: JWTGetToken
  cookie?: string
  key?: string
  credentialsRequired?: boolean
  passthrough?: boolean
  isRevoked?: (ctx: HoaContext, payload: JWTPayload) => boolean | Promise<boolean>
  issuer?: string | string[]
  audience?: string | string[]
  subject?: string
  clockTolerance?: string | number
  jwksUri?: string
}

export function jwt(options?: JWTOptions): HoaMiddleware

export function signJWT(
  payload: JWTPayload,
  secret: string | Uint8Array | CryptoKey | KeyLike,
  options?: {
    algorithm?: string
    issuer?: string
    audience?: string
    subject?: string
    expiresIn?: string | number
    header?: JWSHeaderParameters
  }
): Promise<string>

export function verifyJWT(
  token: string,
  options?: {
    secret?:
      | string
      | Uint8Array
      | CryptoKey
      | KeyLike
      | ((token?: string) => string | Uint8Array | CryptoKey | KeyLike | Promise<string | Uint8Array | CryptoKey | KeyLike>)
    algorithms?: string[]
    issuer?: string | string[]
    audience?: string | string[]
    subject?: string
    clockTolerance?: string | number
    jwksUri?: string
  }
): Promise<{ payload: JWTPayload; protectedHeader: JWSHeaderParameters }>

export default jwt