import nodemailer from 'nodemailer'

export async function eSender(to: string, html: string, subject = 'No Subject'): Promise<void> {
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, EMAIL_FROM } = process.env

  if (!EMAIL_FROM) {
    throw new Error('Email is not configured in current environment')
  }

  if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS) {
    throw new Error('SMTP configuration is missing in current environment')
  }

  const transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT),
    secure: false,
    auth: {
      user: SMTP_USER,
      pass: SMTP_PASS,
    },
  })

  await transporter.sendMail({
    from: EMAIL_FROM,
    to,
    subject,
    html,
  })
}
