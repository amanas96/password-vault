import mongoose from "mongoose";

const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  throw new Error(
    "Please define the MONGODB_URI environment variable inside .env.local"
  );
}

// Define the custom cache structure type
interface MongooseCache {
  conn: typeof mongoose | null;
  promise: Promise<typeof mongoose> | null;
}

// Extend the global object's type to include the custom 'mongoose' property.
// This tells TypeScript that 'global.mongoose' is intentional.
declare global {
  // eslint-disable-next-line no-var
  var mongoose: MongooseCache;
}

// Use the global object for caching (safe in Next.js development environment)
let cached = global.mongoose;

if (!cached) {
  // Initialize the cache structure if it doesn't exist
  cached = global.mongoose = { conn: null, promise: null };
}

async function dbConnect() {
  if (cached.conn) {
    return cached.conn;
  }

  if (!cached.promise) {
    const opts = {
      bufferCommands: false,
    };

    // We use MONGODB_URI! to assert it's defined, based on the check above
    cached.promise = mongoose.connect(MONGODB_URI!, opts).then((mongoose) => {
      return mongoose;
    });
  }
  cached.conn = await cached.promise;
  return cached.conn;
}

export default dbConnect;
