import jwt from 'jsonwebtoken'

type AccessTokenPayload = {
  sub: string
  role: 'user' | 'admin'
  tokenVersion: number
}

type RefreshTokenPayload = {
  sub: string
  tokenVersion: number
}

export function createAccessToken(
  userId: string,
  role: 'user' | 'admin',
  tokenVersion: number
): string {
  const secret = process.env.JWT_ACCESS_SECRET

  if (!secret) {
    throw new Error('JWT_ACCESS_SECRET is not configured')
  }

  const payload: AccessTokenPayload = {
    sub: userId,
    role,
    tokenVersion,
  }

  return jwt.sign(payload, secret, {
    expiresIn: '30m',
  })
}

export function createRefreshToken(userId: string, tokenVersion: number): string {
  const secret = process.env.JWT_REFRESH_SECRET

  if (!secret) {
    throw new Error('JWT_REFRESH_SECRET is not configured')
  }

  const payload: RefreshTokenPayload = {
    sub: userId,
    tokenVersion,
  }

  return jwt.sign(payload, secret, {
    expiresIn: '7d',
  })
}

export function verifyRefreshToken(token: string) {
  return jwt.verify(token, process.env.JWT_REFRESH_SECRET!) as {
    sub: string
    tokenVersion: number
  }
}
