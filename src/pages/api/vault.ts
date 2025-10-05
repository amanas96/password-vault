import { NextApiRequest, NextApiResponse } from "next";
import dbConnect from "../../lib/mongo";
import VaultItem, { IVaultItem } from "../../models/vaultItem";
import jwt from "jsonwebtoken";
import { Types } from "mongoose";

const JWT_SECRET = process.env.JWT_SECRET;

// Middleware to authenticate JWT and extract userId
const authenticateToken = (
  req: NextApiRequest,
  res: NextApiResponse
): Types.ObjectId | null => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).json({ message: "Access token missing or invalid." });
    return null;
  }

  const token = authHeader.split(" ")[1];
  if (!JWT_SECRET) {
    console.error("JWT_SECRET is not defined.");
    return null;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as { userId: string };
    return new Types.ObjectId(decoded.userId);
  } catch (err) {
    res.status(403).json({ message: "Invalid or expired token." });
    return null;
  }
};

export default async function vaultHandler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  await dbConnect();
  const userId = authenticateToken(req, res);

  if (!userId) {
    // Response already sent by authenticateToken
    return;
  }

  try {
    switch (req.method) {
      case "GET":
        // Fetch all encrypted vault items for the user
        const items = await VaultItem.find({ userId });
        return res.status(200).json({ data: items });

      case "POST":
        // Save a new ENCRYPTED vault item
        const { encryptedData, searchableKeywords } = req.body;
        if (!encryptedData) {
          return res
            .status(400)
            .json({ message: "Encrypted data is required." });
        }

        const newItem = await VaultItem.create({
          userId,
          encryptedData,
          searchableKeywords: searchableKeywords || [],
        });
        return res.status(201).json({ data: newItem });

      case "PUT":
        // Update an existing ENCRYPTED vault item
        const { _id, updatedEncryptedData, updatedSearchableKeywords } =
          req.body;

        if (!_id || !updatedEncryptedData) {
          return res.status(400).json({
            message: "ID and encrypted data are required for update.",
          });
        }

        const updatedItem = await VaultItem.findOneAndUpdate(
          { _id, userId }, // Find by ID and ensure it belongs to the user
          {
            encryptedData: updatedEncryptedData,
            searchableKeywords: updatedSearchableKeywords || [],
          },
          { new: true }
        );

        if (!updatedItem) {
          return res
            .status(404)
            .json({ message: "Item not found or unauthorized." });
        }
        return res.status(200).json({ data: updatedItem });

      case "DELETE":
        // Delete a vault item
        const { id } = req.query;

        if (!id) {
          return res.status(400).json({ message: "Item ID is required." });
        }

        const deletedItem = await VaultItem.findOneAndDelete({
          _id: id as string,
          userId,
        });

        if (!deletedItem) {
          return res
            .status(404)
            .json({ message: "Item not found or unauthorized." });
        }
        return res.status(200).json({ message: "Item deleted successfully." });

      default:
        res.setHeader("Allow", ["GET", "POST", "PUT", "DELETE"]);
        return res.status(405).end(`Method ${req.method} Not Allowed`);
    }
  } catch (error) {
    console.error("Vault API error:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
}
