import { NextApiRequest, NextApiResponse } from "next";
import dbConnect from "../../../lib/mongo";
import User from "../../../models/user";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET;

export default async function loginHandler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  await dbConnect();

  if (req.method !== "POST") {
    return res.status(405).json({ message: "Method Not Allowed" });
  }

  const { email, masterPassword } = req.body;

  if (!email || !masterPassword) {
    return res
      .status(400)
      .json({ message: "Email and Master Password are required." });
  }

  if (!JWT_SECRET) {
    console.error("JWT_SECRET is not defined in environment variables.");
    return res.status(500).json({ message: "Server configuration error." });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Invalid credentials." });
    }

    const isMatch = await bcrypt.compare(
      masterPassword,
      user.hashedMasterPassword
    );

    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials." });
    }

    // Generate JWT token for session management
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, {
      expiresIn: "1d",
    });

    // IMPORTANT: The master password is not returned or stored.
    // It remains in the client's memory (state) only for key derivation.

    res.status(200).json({
      token,
      userId: user._id,
      message: "Login successful.",
      // Pass the public salt needed for client-side key derivation
      ENCRYPTION_SALT: process.env.ENCRYPTION_SALT,
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
}
