import { Request, Response, Router } from 'express'
import { authUser } from '../middleware/auth.middleware'
import { checkRole } from '../middleware/role.middleware'

const userRouter = Router()

userRouter.get('/me', authUser, checkRole('user'), (req: Request | any, res: Response) => {
  const user = req.user
  return res.status(200).json(user)
})

export default userRouter
