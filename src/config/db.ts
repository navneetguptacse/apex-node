import mongoose from 'mongoose'

export async function connection() {
  try {
    await mongoose.connect(process.env.MONGO_URI!)
    console.log('Database connection successful')
  } catch (error) {
    console.error('Database connection failed:', error)
    process.exit(1)
  }
}
