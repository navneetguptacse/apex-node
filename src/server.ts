import dotenv from 'dotenv'
import http from 'http'
import app from './app'
import { connection } from './config/db'

dotenv.config()

async function startServer(): Promise<void> {
  try {
    await connection()

    const server = http.createServer(app)

    server.listen(process.env.PORT, () => {
      console.log(`Server running at http://127.0.0.1:${process.env.PORT}`)
    })

    server.on('error', (error) => {
      console.error('Server error:', error)
      process.exit(1)
    })
  } catch (error) {
    console.error('Failed to start server:', error)
    process.exit(1)
  }
}

startServer()
