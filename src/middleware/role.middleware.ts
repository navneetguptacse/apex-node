import { Request, Response, NextFunction } from 'express'

type Role = 'user' | 'admin'

export function checkRole(requiredRole: Role) {
  return (req: Request | any, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ message: 'Unauthorized' })
    }

    if (req.user.role === 'admin') {
      return next()
    }

    if (req.user.role === requiredRole) {
      return next()
    }

    return res.status(403).json({ message: 'Forbidden' })
  }
}
