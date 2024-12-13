import asyncHandler from "express-async-handler";
import User from "../../models/auth/UserModel.js";
import generateToken from "../../helpers/generateToken.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import Token from "../../models/auth/Token.js";
import crypto from "node:crypto";
import hashToken from "../../helpers/hashToken.js";
import sendEmail from "../../helpers/sendEmail.js";

export const registerUser = asyncHandler(async (req, res) => {
    const { name, email, password } = req.body;

    // Validation
    if (!name || !email || !password) {
        // 400 Bad Request
        res.status(400).json({ message: "All fields are required!" });
    }

    // Check password length
    if (password.length < 6) {
        return res
            .status(400)
            .json({ message: "Password must be at least 6 characters!" });
    }

    // Check if User already exists
    const userExists = await User.findOne({ email });

    if (userExists) {
        // Bad Request
        return res.status(400).json({ message: "User already exists!" });
    }

    // Create new User
    const user = await User.create({
        name,
        email,
        password,
    });

    // Generate token with User ID
    const token = generateToken(user._id);

    // Send back the User and token in the response to the client
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      sameSite: "none", // cross-site access --> allow all third-party cookies
      secure: true,
    });

    if (user) {
        const { _id, name, email, role, photo, bio, isVerified } = user;

        // 201 Created
        res.status(201).json({
            _id,
            name,
            email,
            role,
            photo,
            bio,
            isVerified,
            token,
        });
    } else {
        res.status(400).json({ message: "Invalid user data!" });
    }
});

// User login
export const loginUser = asyncHandler(async (req, res) => {
    // Get eamil and password from req.body
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
        // 400 Bad Request
        return res.status(400).json({ message: "All fields are required!" });
    }

    // Check if user exists
    const userExists = await User.findOne({ email });

    if (!userExists) {
        return res.status(404).json({ message: "User not found, Sign Up!" });
    }

    // Check if the password match the hashed password in the Database
    const isMatch = await bcrypt.compare(password, userExists.password);

    if (!isMatch) {
        // 400 Bad Request
        return res.status(400).json({ message: "Invalid Credentials!" });
    }

    // Generate token with user ID
    const token = generateToken(userExists._id);

    if(userExists && isMatch) {
        const { _id, name, email, role, photo, bio, isVerified } = userExists;

        // Set the token in the Cookie
        res.cookie("token", token, {
            path: "/",
            httpOnly: 30 * 24 * 60 * 60 * 1000, // 30 days
            sameSite: true,
            secure: true,
        });

        // Send back the user and token in the response to the Client
        res.status(200).json({
            _id,
            name,
            email,
            role,
            photo,
            bio,
            isVerified,
            token,
        });
    } else{
        res.status(400).json({ message: "Invalid email or password!" });
    }
});

// Logout user
export const logoutUser = asyncHandler(async (req, res) => {
    res.clearCookie("token", {
        httpOnly: true,
        sameSite: "none",
        secure: true,
        path: "/",
    });

    res.status(200).json({ message: "Successfully logged out!" });
});
  

// Get User
export const getUser = asyncHandler(async (req, res) => {
    // Get User details from the token ----> Exclude password
    const user = await User.findById(req.user._id).select("-password");

    if (user) {
        res.status(200).json(user);
    } else {
        // 404 Not found
        res.status(404).json({ message: "User not found!" });
    }
});

    // Update User
    export const updateUser = asyncHandler(async (req, res) => {
        // Get User details from the token ---> Protect Middleware
        const user = await User.findById(req.user._id);

        if (user) {
            // User properties to update
            const { name, bio, photo } = req.body;
            // Update User properties
            user.name = req.body.name || user.name;
            user.bio = req.body.bio || user.bio;
            user.photo = req.body.photo || user.photo;

            const updated = await user.save();

        res.status(200).json({
            _id: updated._id,
            name: updated.name,
            email: updated.email,
            role: updated.role,
            photo: updated.photo,
            bio: updated.bio,
            isVerified: updated.isVerified,
            });
        } else {
            // 404 Not Found
            res.status(404).json({ message: "User not found!" });
        }
});

// Login status
export const userLoginStatus = asyncHandler(async (req, res) => {
    const token = req.cookies.token;
  
    if (!token) {
      // 401 Unauthorized
      res.status(401).json({ message: "Not authorized, please login!" });
    }
    // verify the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
  
    if (decoded) {
      res.status(200).json(true);
    } else {
      res.status(401).json(false);
    }
  });

  // Email verification
  export const verifyEmail = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    // If User exists
    if(!user) {
        return res.status(404).json({ message: "User not found!" });
    }

    // Check if user is already verified
    if(user.isVerified) {
        return res.status(400).json({ message: "User is already verified!" });
    }

    let token = await Token.findOne({ userId: user._id });

    // If token exists --> Delete the token
    if (token) {
        await token.deleteOne();
    }

    // Create a verification token using the User id --->
  const verificationToken = crypto.randomBytes(64).toString("hex") + user._id;

  // Hash the verification token
  const hashedToken = hashToken(verificationToken);

  await new Token({
    userId: user._id,
    verificationToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 24 * 60 * 60 * 1000, // 24 hours
  }).save();

// Verification link
const verificationLink = `${process.env.CLIENT_URL}/verify-email/${verificationToken}`;

// Send email
const subject = "Email Verification - Druit";
const send_to = user.email;
const reply_to = "noreply@gmail.com";
const template = "emailVerification";
const send_from = process.env.USER_EMAIL;
const name = user.name;
const url = verificationLink;

try {
  // Order matters ---> Subject, Send_to, Send_from, Reply_to, Template, Name, URL
  await sendEmail(subject, send_to, send_from, reply_to, template, name, url);
  return res.json({ message: "Email sent!" });
} catch (error) {
  console.log("Error sending email: ", error);
  return res.status(500).json({ message: "Email could not be sent!" });
}
});

// Verifiy User
export const verifyUser = asyncHandler(async (req, res) => {
    const { verificationToken } = req.params;

    if(!verificationToken){
        return res.status(400).json({ message: "Invalid verification token!" });
    }

// Hash the verification token --> Because it was hashed before saving
const hashedToken = hashToken(verificationToken);

// Find User with the verification token
const userToken = await Token.findOne({
  verificationToken: hashedToken,
  // Check if the token has not expired
  expiresAt: { $gt: Date.now() },
});

if (!userToken) {
  return res
    .status(400)
    .json({ message: "Invalid or expired verification token!" });
}

// Find User with the user ID in the token
const user = await User.findById(userToken.userId);

if (user.isVerified) {
  // 400 Bad Request
  return res.status(400).json({ message: "User is already verified!" });
}

// Update User to verified
user.isVerified = true;
await user.save();
res.status(200).json({ message: "User verified!" });
});

// Forgot password
export const forgotPassword = asyncHandler(async (req, res) => {
    const { email } = req.body;
  
    if (!email) {
      return res.status(400).json({ message: "Email is required!" });
    }
  
    // Check if User exists
    const user = await User.findOne({ email });
  
    if (!user) {
      // 404 Not Found
      return res.status(404).json({ message: "User not found!" });
    }
  
    // See if reset token exists
    let token = await Token.findOne({ userId: user._id });
  
    // If token exists --> Delete the token
    if (token) {
      await token.deleteOne();
    }
  
    // Create a reset token using the user ID ---> expires in 1 hour
    const passwordResetToken = crypto.randomBytes(64).toString("hex") + user._id;
  
    // Hash the reset token
    const hashedToken = hashToken(passwordResetToken);
  
    await new Token({
      userId: user._id,
      passwordResetToken: hashedToken,
      createdAt: Date.now(),
      expiresAt: Date.now() + 60 * 60 * 1000, // 1 hour
    }).save();
  
    // Reset link
    const resetLink = `${process.env.CLIENT_URL}/reset-password/${passwordResetToken}`;
  
    // Send email to User
    const subject = "Password Reset - Druit";
    const send_to = user.email;
    const send_from = process.env.USER_EMAIL;
    const reply_to = "noreply@noreply.com";
    const template = "forgotPassword";
    const name = user.name;
    const url = resetLink;
  
    try {
      await sendEmail(subject, send_to, send_from, reply_to, template, name, url);
      res.json({ message: "Email sent!" });
    } catch (error) {
      console.log("Error sending email: ", error);
      return res.status(500).json({ message: "Email could not be sent!" });
    }
  });
  
  // Reset password
  export const resetPassword = asyncHandler(async (req, res) => {
    const { resetPasswordToken } = req.params;
    const { password } = req.body;
  
    if (!password) {
      return res.status(400).json({ message: "Password is required!" });
    }
  
    // Hash the reset token
    const hashedToken = hashToken(resetPasswordToken);
  
    // Check if token exists and has not expired
    const userToken = await Token.findOne({
      passwordResetToken: hashedToken,
      // Check if the token has not expired
      expiresAt: { $gt: Date.now() },
    });
  
    if (!userToken) {
      return res.status(400).json({ message: "Invalid or expired reset token!" });
    }
  
    // Find User with the User ID in the token
    const user = await User.findById(userToken.userId);
  
    // Update User password
    user.password = password;
    await user.save();
  
    res.status(200).json({ message: "Password reset successfully!" });
  });

  // Change password
export const changePassword = asyncHandler(async (req, res) => {
    const { currentPassword, newPassword } = req.body;
  
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: "All fields are required!" });
    }
  
    // Find user by id
    const user = await User.findById(req.user._id);
  
    // Compare current password with the hashed password in the database
    const isMatch = await bcrypt.compare(currentPassword, user.password);
  
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid password!" });
    }
  
    // Reset password
    if (isMatch) {
      user.password = newPassword;
      await user.save();
      return res.status(200).json({ message: "Password changed successfully!" });
    } else {
      return res.status(400).json({ message: "Password could not be changed!" });
    }
});