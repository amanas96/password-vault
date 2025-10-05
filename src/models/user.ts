import mongoose, { Schema, Document } from "mongoose";

export interface IUser extends Document {
  email: string;

  hashedMasterPassword: string;
}

const UserSchema: Schema = new Schema(
  {
    email: { type: String, required: true, unique: true },
    hashedMasterPassword: { type: String, required: true },
  },
  { timestamps: true }
);

const User = mongoose.models.User || mongoose.model<IUser>("User", UserSchema);

export default User;
