import mongoose, { Document, Schema } from "mongoose";
import bcrypt from "bcryptjs";

// 1. Define the TypeScript interface for User Document
export interface IUser extends Document {
  name: string;
  email: string;
  password: string;
  image?: string;
  role: "user" | "admin"; // add more roles if needed
  resetToken?: string;
  resetTokenExpiry?: Date;
  createdAt: Date;

  comparePassword(candidatePassword: string): Promise<boolean>;
}

// 2. Define the Mongoose schema
const UserSchema: Schema<IUser> = new Schema<IUser>({
  name: { type: String, required: true },
  email: {
    type: String,
    unique: true,
    required: [true, "Email is required"],
    match: [
      /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/,
      "Please provide a valid email",
    ],
  },
  password: {
    type: String,
    required: [true, "Password is required"],
    minlength: [6, "Password must be at least 6 characters"],
  },
  image: { type: String, default: "" },
  role: {
    type: String,
    enum: ["user", "admin"],
    default: "user",
  },
  resetToken: { type: String },
  resetTokenExpiry: { type: Date },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// 3. Hash password before saving
UserSchema.pre<IUser>("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

// 4. Add method to compare passwords
UserSchema.methods.comparePassword = async function (
  candidatePassword: string
): Promise<boolean> {
  return await bcrypt.compare(candidatePassword, this.password);
};

// 5. Export the model
const User = mongoose.model<IUser>("User", UserSchema);
export default User;
