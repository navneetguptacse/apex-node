import { Request, Response, NextFunction } from 'express'
import { verifyAccessToken } from '../lib/token'
import { User } from '../models/user.model'

export async function authUser(req: Request | any, res: Response, next: NextFunction) {
  const token = req.headers.authorization?.replace('Bearer ', '')

  if (!token) {
    return res.status(401).json({ message: 'Unauthorized' })
  }

  try {
    const payload = verifyAccessToken(token)

    const user = await User.findById(payload.sub)

    if (!user) {
      return res.status(401).json({ message: 'User not found' })
    }

    if (user.tokenVersion !== payload.tokenVersion) {
      return res.status(401).json({ message: 'Token has been revoked' })
    }

    req.user = {
      id: payload.sub,
      name: user.name,
      email: user.email,
      role: payload.role,
      tokenVersion: payload.tokenVersion,
      isVerified: user.isVerified,
    }

    return next()
  } catch {
    return res.status(401).json({ message: 'Invalid token' })
  }
}
