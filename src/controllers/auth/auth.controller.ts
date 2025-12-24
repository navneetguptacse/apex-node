import crypto from 'crypto'
import { Request, Response } from 'express'
import jwt from 'jsonwebtoken'
import { eSender } from '../../lib/email'
import { checkPassword, hashPassword } from '../../lib/hash'
import { createAccessToken, createRefreshToken, verifyRefreshToken } from '../../lib/token'
import { User } from '../../models/user.model'
import { loginSchema, registerSchema } from './auth.schema'

export async function registerHandler(req: Request, res: Response) {
  try {
    const parsed = registerSchema.safeParse(req.body)
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: parsed.error.flatten().fieldErrors,
      })
    }
    const { name, email, password } = parsed.data

    const normalizedEmail = email.toLowerCase().trim()

    const existingUser = await User.findOne({ email: normalizedEmail })
    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: 'User already exists',
      })
    }
    const hashedPassword = await hashPassword(password)
    const user = await User.create({
      name,
      email: normalizedEmail,
      hashedPassword,
    })

    if (!process.env.JWT_ACCESS_SECRET) {
      throw new Error('JWT_ACCESS_SECRET is not configured')
    }

    const token = jwt.sign({ sub: user.id.toString() }, process.env.JWT_ACCESS_SECRET, {
      expiresIn: '1d',
    })

    if (!process.env.APP_URL) {
      throw new Error('APP_URL is not configured')
    }

    const verifyLink = `${process.env.APP_URL}/auth/verify?token=${token}`

    const subject = 'Verify your email'
    const html = `
      <h2>Welcome, ${user.name}</h2>
      <p>Please verify your email by clicking the link below:</p>
      <p><a href="${verifyLink}">${verifyLink}</a></p>
    `
    await eSender(user.email, html, subject)
    return res.status(201).json({
      success: true,
      message: 'Registration successful. Please verify your email.',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        isVerified: user.isVerified,
      },
    })
  } catch (err) {
    console.error('Register error:', err)

    return res.status(500).json({
      success: false,
      message: 'Internal server error',
    })
  }
}

export async function verifyHandler(req: Request, res: Response) {
  const token = req.query.token

  if (typeof token !== 'string') {
    return res.status(400).json({
      success: false,
      message: 'Verification token is missing',
    })
  }

  if (!process.env.JWT_ACCESS_SECRET) {
    return res.status(500).json({
      success: false,
      message: 'Server configuration error',
    })
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET) as {
      sub: string
    }

    const user = await User.findById(payload.sub)

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      })
    }

    if (user.isVerified) {
      return res.status(409).json({
        success: true,
        message: 'Email already verified',
      })
    }

    user.isVerified = true
    await user.save()

    return res.status(200).json({
      success: true,
      message: 'Email verified successfully',
    })
  } catch (err) {
    console.error('Email verification error:', err)

    return res.status(400).json({
      success: false,
      message: 'Invalid or expired verification token',
    })
  }
}

export async function loginHandler(req: Request, res: Response) {
  try {
    const parsed = loginSchema.safeParse(req.body)
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: parsed.error.flatten().fieldErrors,
      })
    }

    const { email, password } = parsed.data
    const normalizedEmail = email.toLowerCase().trim()

    const user = await User.findOne({ email: normalizedEmail })
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password',
      })
    }

    const isPasswordValid = await checkPassword(password, user.hashedPassword)

    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password',
      })
    }

    if (!user.isVerified) {
      return res.status(403).json({
        success: false,
        message: 'Please verify your email before logging in',
      })
    }

    const accessToken = createAccessToken(user._id.toString(), user.role, user.tokenVersion)

    const refreshToken = createRefreshToken(user._id.toString(), user.tokenVersion)

    const isProd = process.env.NODE_ENV === 'production'

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    })

    return res.status(200).json({
      success: true,
      accessToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        isVerified: user.isVerified,
      },
    })
  } catch (err) {
    console.error('Login error:', err)

    return res.status(500).json({
      success: false,
      message: 'Internal server error',
    })
  }
}

export async function refreshHandler(req: Request, res: Response) {
  try {
    const token = req.cookies?.refreshToken as string | undefined

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Refresh token missing',
      })
    }

    const payload = verifyRefreshToken(token)

    const user = await User.findById(payload.sub)
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User not found',
      })
    }

    if (user.tokenVersion !== payload.tokenVersion) {
      return res.status(401).json({
        success: false,
        message: 'Refresh token revoked',
      })
    }

    const newAccessToken = createAccessToken(user.id, user.role, user.tokenVersion)

    const newRefreshToken = createRefreshToken(user.id, user.tokenVersion)

    const isProd = process.env.NODE_ENV === 'production'

    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    })

    return res.status(200).json({
      success: true,
      message: 'Token refreshed successfully',
      accessToken: newAccessToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        isVerified: user.isVerified,
      },
    })
  } catch (error) {
    console.error('Refresh token error:', error)

    return res.status(401).json({
      success: false,
      message: 'Invalid or expired refresh token',
    })
  }
}

export async function logoutHandler(req: Request, res: Response) {
  try {
    const refreshToken = req.cookies?.refreshToken as string | undefined

    if (!refreshToken) {
      return res.status(200).json({
        success: true,
        message: 'Already logged out',
      })
    }

    const payload = verifyRefreshToken(refreshToken)
    const userId = payload.sub

    await User.findByIdAndUpdate(userId, {
      $inc: { tokenVersion: 1 },
    })

    res.clearCookie('refreshToken', {})

    return res.status(200).json({
      success: true,
      message: 'Logged out successfully',
    })
  } catch (error) {
    console.error('Logout error:', error)

    res.clearCookie('refreshToken', {})

    return res.status(200).json({
      success: true,
      message: 'Logged out successfully',
    })
  }
}

export async function resetHandler(req: Request, res: Response) {
  try {
    const { email } = req.body as { email?: string }

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required',
      })
    }

    const normalizedEmail = email.toLowerCase().trim()

    const user = await User.findOne({ email: normalizedEmail })

    if (!user) {
      return res.status(200).json({
        success: true,
        message: 'If an account exists, a reset link has been sent',
      })
    }

    const resetToken = jwt.sign(
      {
        sub: user._id,
        tokenVersion: user.tokenVersion,
      },
      process.env.RESET_TOKEN_SECRET as string,
      {
        expiresIn: '15m',
      }
    )

    const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex')

    user.resetPasswordToken = hashedToken
    user.resetPasswordExpires = new Date(Date.now() + 15 * 60 * 1000) // 15 mins

    await user.save()

    const resetLink = `${process.env.APP_URL}/auth/reset-password?token=${resetToken}`
    const subject = 'Reset your password'
    const html = `
        <p>You requested a password reset.</p>
        <p>Click the link below to reset your password:</p>
        <p><a href="${resetLink}">${resetLink}</a></p>
        <p>This link expires in 15 minutes.</p>
      `
    await eSender(user.email, html, subject)

    return res.status(200).json({
      success: true,
      message: 'If an account exists, a reset link has been sent',
    })
  } catch (error) {
    console.error('Reset password error:', error)
    return res.status(500).json({
      success: false,
      message: 'Something went wrong',
    })
  }
}

export async function resetPasswordHandler(req: Request, res: Response) {
  const { token } = req.query as { token?: string }
  const { password } = req.body as { password?: string }

  if (!token) {
    return res.status(400).json({
      success: false,
      message: 'Reset token is required',
    })
  }

  if (!password || password.length < 8) {
    return res.status(400).json({
      success: false,
      message: 'Password must be at least 8 characters long',
    })
  }

  try {
    const decoded = jwt.verify(token, process.env.RESET_TOKEN_SECRET as string) as {
      sub: string
      tokenVersion: number
    }

    const hashedToken = crypto.createHash('sha256').update(token).digest('hex')

    const user = await User.findOne({
      _id: decoded.sub,
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: new Date() },
    })

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired reset token',
      })
    }

    if (user.tokenVersion !== decoded.tokenVersion) {
      return res.status(400).json({
        success: false,
        message: 'Reset token is no longer valid',
      })
    }

    const hashedPassword = await hashPassword(password)

    user.hashedPassword = hashedPassword
    user.tokenVersion += 1
    user.resetPasswordToken = undefined
    user.resetPasswordExpires = undefined

    await user.save()

    return res.status(200).json({
      success: true,
      message: 'Password has been reset successfully',
    })
  } catch (err) {
    return res.status(400).json({
      success: false,
      message: 'Invalid or expired reset token',
    })
  }
}
