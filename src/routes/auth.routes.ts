import { Router } from 'express'
import {
  loginHandler,
  logoutHandler,
  refreshHandler,
  registerHandler,
  resetHandler,
  resetPasswordHandler,
  verifyHandler,
} from '../controllers/auth/auth.controller'

const authRouter = Router()

authRouter.post('/register', registerHandler)
authRouter.post('/login', loginHandler)
authRouter.get('/verify', verifyHandler)
authRouter.post('/refresh', refreshHandler)
authRouter.post('/logout', logoutHandler)
authRouter.post('/forgot-password', resetHandler)
authRouter.post('/reset-password', resetPasswordHandler)

export default authRouter
