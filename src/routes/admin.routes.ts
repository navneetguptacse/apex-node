import { Request, Response, Router } from 'express'
import { authUser } from '../middleware/auth.middleware'
import { checkRole } from '../middleware/role.middleware'
import { User } from '../models/user.model'

const adminRouter = Router()

adminRouter.get('/users', authUser, checkRole('admin'), async (_req: Request, res: Response) => {
  try {
    const users = await User.find(
      {},
      {
        name: 1,
        email: 1,
        role: 1,
        isVerified: 1,
        createdAt: 1,
      }
    ).sort({ createdAt: -1 })

    return res.status(200).json({
      success: true,
      data: users,
    })
  } catch (err) {
    console.error('Admin users fetch error:', err)
    return res.status(500).json({
      success: false,
      message: 'Failed to fetch users',
    })
  }
})

export default adminRouter
