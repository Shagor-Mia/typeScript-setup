import { Request, Response } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import User from "../models/user.model";
import cloudinary from "../utils/cloudinary";
import { sendEmail } from "../utils/otp";

const generateToken = (id: string) => {
  return jwt.sign({ id }, process.env.JWT_SECRET!, { expiresIn: "5h" });
};

// Register
export const register = async (req: Request, res: Response) => {
  try {
    const { name, email, password, confirmPassword } = req.body;
    if (!name || !email || !password || !confirmPassword) {
      return res.status(400).json({ message: "All fields are required" });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ message: "Passwords do not match" });
    }
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    let imageUrl = "";
    if (req.file) {
      const localPath = path.join(__dirname, "../uploads", req.file.filename);
      const result = await cloudinary.uploader.upload(localPath, {
        folder: "user_images",
      });
      imageUrl = result.secure_url;
      fs.unlinkSync(localPath);
    }

    const newUser = new User({ name, email, password, image: imageUrl });
    await newUser.save();

    res.status(201).json({
      success: true,
      message: "User registered successfully",
      user: {
        id: newUser._id,
        name: newUser.name,
        email: newUser.email,
        image: newUser.image,
      },
    });
  } catch (error: any) {
    res.status(500).json({ message: error.message });
  }
};

// Login
export const login = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required" });
    }
    const user = await User.findOne({ email });
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ message: "Invalid credentials" });
    }
    const token = generateToken(user._id as string);
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 5 * 3600000,
    });
    res.status(200).json({
      success: true,
      message: "Login successful",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        image: user.image,
      },
    });
  } catch (error: any) {
    res.status(500).json({ message: error.message });
  }
};

// Forgot Password
export const forgotPassword = async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    user.resetToken = otp;
    user.resetTokenExpiry = new Date(Date.now() + 15 * 60 * 1000);
    await user.save();

    const html = `
      <p>Your OTP for password reset is: <strong>${otp}</strong></p>
      <p>This OTP will expire in 15 minutes.</p>
    `;
    await sendEmail(user.email, "Password Reset OTP", html);

    res.status(200).json({ message: "OTP sent to email" });
  } catch (error: any) {
    res.status(500).json({ message: error.message });
  }
};

// Reset Password
export const resetPassword = async (req: Request, res: Response) => {
  try {
    const { email, otp, password, confirmPassword } = req.body;
    if (!email || !otp || !password || !confirmPassword) {
      return res.status(400).json({ message: "All fields are required" });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ message: "Passwords do not match" });
    }
    const user = await User.findOne({
      email,
      resetToken: otp,
      resetTokenExpiry: { $gt: new Date() },
    });
    if (!user) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }
    user.password = password;
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    await user.save();

    const html = `<p>Your password has been successfully reset.</p>`;
    await sendEmail(user.email, "Password Reset Successful", html);

    res.status(200).json({ message: "Password reset successful" });
  } catch (error: any) {
    res.status(500).json({ message: error.message });
  }
};

// Logout
export const logout = (req: Request, res: Response) => {
  res.clearCookie("token");
  res.status(200).json({ message: "Logged out successfully" });
};

// Update Account
export const updateAccount = async (req: Request, res: Response) => {
  try {
    const userId = req.user.id;
    const { name, email, currentPassword, newPassword, confirmNewPassword } =
      req.body;
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (name) user.name = name;
    if (email && email !== user.email) {
      const emailExists = await User.findOne({ email });
      if (emailExists) {
        return res.status(400).json({ message: "Email already in use" });
      }
      user.email = email;
    }

    if (currentPassword && newPassword) {
      if (!confirmNewPassword) {
        return res
          .status(400)
          .json({ message: "Please confirm your new password" });
      }
      if (newPassword !== confirmNewPassword) {
        return res.status(400).json({ message: "New passwords do not match" });
      }
      if (!(await user.comparePassword(currentPassword))) {
        return res
          .status(401)
          .json({ message: "Current password is incorrect" });
      }
      user.password = newPassword;
    }

    if (req.file) {
      if (user.image) {
        const publicId = user.image.split("/").pop()?.split(".")[0];
        if (publicId) {
          await cloudinary.uploader.destroy(`user_images/${publicId}`);
        }
      }
      const localPath = path.join(__dirname, "../uploads", req.file.filename);
      const result = await cloudinary.uploader.upload(localPath, {
        folder: "user_images",
      });
      user.image = result.secure_url;
      fs.unlinkSync(localPath);
    }

    await user.save();
    res.status(200).json({
      success: true,
      message: "Account updated successfully",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        image: user.image,
      },
    });
  } catch (error: any) {
    res.status(500).json({ message: error.message });
  }
};

// Delete Account
export const deleteAccount = async (req: Request, res: Response) => {
  try {
    const userId = req.user.id;
    const { password } = req.body;

    if (!password) {
      return res
        .status(400)
        .json({ message: "Password is required to delete account" });
    }

    const user = await User.findById(userId);
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ message: "Password is incorrect" });
    }

    // Delete image from Cloudinary if exists
    if (user.image && user.image.includes("cloudinary")) {
      const publicId = user.image.split("/").pop()?.split(".")[0];
      if (publicId) {
        await cloudinary.uploader.destroy(publicId);
      }
    }

    // Delete local image if exists and not a Cloudinary URL
    if (user.image && !user.image.includes("cloudinary")) {
      const imagePath = path.join(__dirname, "..", "uploads", user.image);
      if (fs.existsSync(imagePath)) {
        fs.unlinkSync(imagePath);
      }
    }

    await User.findByIdAndDelete(userId);
    res.status(200).json({ message: "Account deleted successfully" });
  } catch (error) {
    console.error("Delete Account Error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};
