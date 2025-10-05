import { NextApiRequest, NextApiResponse } from "next";
import dbConnect from "../../../lib/mongo";
import User from "../../../models/user";
import bcrypt from "bcryptjs";

export default async function signupHandler(
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

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "User already exists." });
    }

    // Hash the master password using bcrypt
    const salt = await bcrypt.genSalt(10);
    const hashedMasterPassword = await bcrypt.hash(masterPassword, salt);

    const newUser = await User.create({
      email,
      hashedMasterPassword,
    });

    res.status(201).json({
      message: "User created successfully. Please log in.",
      userId: newUser._id,
    });
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
}
