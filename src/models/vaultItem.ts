import mongoose, { Schema, Document } from "mongoose";

// The server-side model only cares about storing the ENCRYPTED data.
// The actual plaintext structure (title, password, etc.) is only known on the client.
export interface IVaultItem extends Document {
  userId: mongoose.Types.ObjectId;
  // This field stores the result of the client-side encryption (ciphertext + IV)
  // The server never sees the plaintext.
  encryptedData: string;
  // We can also store an unencrypted searchable key (e.g., lowercase title/username)
  // to enable server-side searching without decrypting.
  searchableKeywords: string[];
}

const VaultItemSchema: Schema = new Schema(
  {
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true },
    encryptedData: { type: String, required: true },
    searchableKeywords: { type: [String], default: [] }, // For basic server-side search
  },
  { timestamps: true }
);

// Check if the model already exists to prevent re-compilation in development
const VaultItem =
  mongoose.models.VaultItem ||
  mongoose.model<IVaultItem>("VaultItem", VaultItemSchema);

export default VaultItem;
