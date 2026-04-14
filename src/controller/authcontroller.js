import User from "../model/User.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { upsertStreamUser } from "../lib/stream.js";
import { OAuth2Client } from "google-auth-library";
import { sendVerificationEmail, sendMFAMail } from "../lib/mail.js";
import cloudinary from "../lib/cloudinary.js";

dotenv.config();

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

export const registerUser = async (req, res) => {
  try {
    const { FullName, Email, Password } = req.body;

    if (!FullName || !Email || !Password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    if (Password.length < 6) {
      return res
        .status(400)
        .json({ message: "Password must be at least 6 characters long" });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(Email)) {
      return res.status(400).json({ message: "Invalid email format" });
    }

    const usercheck = await User.findOne({ Email });

    if (usercheck) {
      if (usercheck.isVerified) {
        return res.status(400).json({ message: "User already exists" });
      } else {
        // User exists but is not verified. Update OTP and resend email.
        const hashedPassword = await bcrypt.hash(Password, 10);
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

        usercheck.FullName = FullName;
        usercheck.Password = hashedPassword;
        usercheck.otp = otp;
        usercheck.otpExpires = otpExpires;
        // profilePic stays same or update if needed

        await usercheck.save();

        try {
          await sendVerificationEmail(Email, otp);
        } catch (emailError) {
          console.log("Error resending verification email:", emailError.message);
          // Don't fail resend if email fails
        }

        return res.status(200).json({
          message: "Verification code resent.",
          userId: usercheck._id,
          needVerification: true,
        });
      }
    }

    const hashedPassword = await bcrypt.hash(Password, 10);

    const idx = Math.floor(Math.random() * 100) + 1;
    const randomavatar = `https://avatar.iran.liara.run/public/${idx}`;

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    const newUser = await User.create({
      FullName,
      Email,
      Password: hashedPassword,
      profilePic: randomavatar,
      otp,
      otpExpires,
      isVerified: false,
    });

    try {
      await sendVerificationEmail(Email, otp);
    } catch (emailError) {
      console.log("Error sending verification email:", emailError.message);
      // Don't fail signup if email fails, user can retry
    }

    return res.status(201).json({
      message: "OTP sent to your email. Please verify.",
      userId: newUser._id,
      needVerification: true,
    });
  } catch (error) {
    console.log("error in register user", error);
    return res.status(500).json({ message: error.message });
  }
};

export const verifyEmail = async (req, res) => {
  try {
    const { userId, otp } = req.body;

    if (!userId || !otp) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const user = await User.findById(userId);

    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    if (user.isVerified) {
      return res.status(400).json({ message: "User already verified" });
    }

    if (user.otp !== otp || user.otpExpires < Date.now()) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    user.isVerified = true;
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    try {
      await upsertStreamUser({
        id: user._id.toString(),
        name: user.FullName,
        image: user.profilePic || "",
      });
    } catch (error) {
      console.log("error upserting stream user", error);
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    res.cookie("jwt", token, {
      maxAge: 7 * 24 * 60 * 60 * 1000,
      httpOnly: true,
      secure: true, // Always true for sameSite: "none"
      sameSite: "none",
    });

    return res
      .status(200)
      .json({ message: "Email verified successfully", user, token });
  } catch (error) {
    console.log("error in verify email", error);
    return res.status(500).json({ message: error.message });
  }
};

export const loginUser = async (req, res) => {
  try {
    const { Email, Password } = req.body;

    if (!Email || !Password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const usercheck = await User.findOne({ Email });

    if (!usercheck) {
      return res.status(400).json({ message: "User does not exist" });
    }

    const isPasswordMatch = await bcrypt.compare(Password, usercheck.Password);
    if (!isPasswordMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    if (!usercheck.isVerified) {
      return res
        .status(400)
        .json({ message: "Please verify your email first" }); // Or handle re-sending OTP
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    usercheck.otp = otp;
    usercheck.otpExpires = otpExpires;
    await usercheck.save();

    await sendMFAMail(Email, otp);

    return res.status(200).json({
      message: "MFA code sent to your email",
      mfaRequired: true,
      userId: usercheck._id,
    });
  } catch (error) {
    console.log("error in login user", error);
    return res.status(500).json({ message: error.message });
  }
};

export const verifyMFA = async (req, res) => {
  try {
    const { userId, otp } = req.body;

    if (!userId || !otp) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const user = await User.findById(userId);

    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    if (user.otp !== otp || user.otpExpires < Date.now()) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    res.cookie("jwt", token, {
      maxAge: 7 * 24 * 60 * 60 * 1000,
      httpOnly: true,
      secure: true,
      sameSite: "none",
    });

    res.status(200).json({ message: "MFA successful", user, token });
  } catch (error) {
    console.log("error in verify MFA", error);
    res.status(500).json({ message: error.message });
  }
};

export const logoutUser = async (req, res) => {
  try {
    res.clearCookie("jwt", {
      httpOnly: true,
      secure: true,
      sameSite: "none",
    });
    return res.status(200).json({ message: "User logged out successfully" });
  } catch (error) {
    console.log("error in logout", error);
    res.status(500).json({ message: error.message });
  }
};

export const onboard = async (req, res) => {
  try {
    const userId = req.user._id;
    const { FullName, bio, nativeLanguage, learningLanguage, location } =
      req.body;
    let profilePic = req.body.profilePic;

    if (profilePic && profilePic.startsWith("data:image")) {
      const uploadResponse = await cloudinary.uploader.upload(profilePic, {
        folder: "chat_app_profiles",
      });
      profilePic = uploadResponse.secure_url;
    }

    if (
      !FullName ||
      !bio ||
      !nativeLanguage ||
      !learningLanguage ||
      !location
    ) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      {
        FullName: FullName,
        bio,
        nativeLanguage,
        learningLanguage,
        location,
        profilePic,
        isOnboarded: true,
      },
      { new: true },
    );

    if (!updatedUser) {
      return res.status(400).json({ message: "User not found" });
    }

    try {
      await upsertStreamUser({
        id: updatedUser._id.toString(),
        name: updatedUser.FullName,
        image: updatedUser.profilePic || "",
      });
    } catch (error) {
      console.log("error in upsertStreamUser", error);
      // Don't fail the request if stream fails, just log it
    }

    return res.status(200).json({ success: true, user: updatedUser });
  } catch (error) {
    console.log("error in onboard", error);
    return res.status(500).json({ message: error.message });
  }
};

export const updateProfile = async (req, res) => {
  try {
    const userId = req.user._id;
    const { FullName, bio, nativeLanguage, learningLanguage, location } =
      req.body;
    let profilePic = req.body.profilePic;

    if (profilePic && profilePic.startsWith("data:image")) {
      const uploadResponse = await cloudinary.uploader.upload(profilePic, {
        folder: "chat_app_profiles",
      });
      profilePic = uploadResponse.secure_url;
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      {
        FullName,
        bio,
        nativeLanguage,
        learningLanguage,
        location,
        ...(profilePic && { profilePic }),
      },
      { new: true },
    );

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    try {
      await upsertStreamUser({
        id: updatedUser._id.toString(),
        name: updatedUser.FullName,
        image: updatedUser.profilePic || "",
      });
    } catch (error) {
      console.log("error updating stream user", error);
    }

    res.status(200).json({ success: true, user: updatedUser });
  } catch (error) {
    console.log("error in update profile", error);
    res.status(500).json({ message: error.message });
  }
};

export const checkAuth = async (req, res) => {
  try {
    res.status(200).json(req.user);
  } catch (error) {
    console.log("Error in checkAuth controller", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

export const googleAuth = async (req, res) => {
  try {
    const { credential } = req.body;
    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const { email, name, picture, sub } = payload;

    let user = await User.findOne({ Email: email });

    if (!user) {
      const randomPassword = Math.random().toString(36).slice(-8);
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(randomPassword, salt);

      user = await User.create({
        FullName: name,
        Email: email,
        Password: hashedPassword,
        profilePic: picture,
        isVerified: true,
      });

      try {
        await upsertStreamUser({
          id: user._id.toString(),
          name: user.FullName,
          image: user.profilePic || "",
        });
      } catch (error) {
        console.log("error creating stream user", error);
      }
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    res.cookie("jwt", token, {
      maxAge: 7 * 24 * 60 * 60 * 1000,
      httpOnly: true,
      secure: true,
      sameSite: "none",
    });

    res.status(200).json({ message: "Google login successful", user, token });
  } catch (error) {
    console.log("error in google auth", error);
    res.status(500).json({ message: error.message });
  }
};
