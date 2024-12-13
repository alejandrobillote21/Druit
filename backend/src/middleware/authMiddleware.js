import asyncHandler from "express-async-handler";
import jwt from "jsonwebtoken";
import User from "../models/auth/UserModel.js";

export const protect = asyncHandler(async (req, res, next) => {
    try {
        // Check if User is Logged in
        const token = req.cookies.token;

        if (!token) {
            // 401 Unauthorized
            res.status(401).json({ message: "Not authorized, please login!" });
        }

        // Verify the token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Get User details from the token -----> Exclude password
        const user = await User.findById(decoded.id).select("-password");

        // Check if User exists
        if(!user) {
            res.status(404).json({ message: "User not found!" });
        }

        // Set User details in the request object
        req.user = user;

        next();
      } catch (error) {
        // 401 Unauthorized
        res.status(401).json({ message: "Not authorized, token failed!" });
      }
});

// Admin Middleware
export const adminMiddleware = asyncHandler(async (req, res, next) => {
    if(req.user && req.user.role === "admin") {
        // If user is Admin, move to the next Middleware/Controller
        next();
        return;
    }
    // If not Admin, send 403 Forbidden ---> Terminate the request
    res.status(403).json({ message: "Administration rights required!" })
});

export const creatorMiddleware = asyncHandler(async (req, res, next) => {
    if (
      (req.user && req.user.role === "creator") ||
      (req.user && req.user.role === "admin")
    ) {
      // If user is creator, move to the next Middleware/Controller
      next();
      return;
    }
    // If not creator, send 403 Forbidden --> terminate the request
    res.status(403).json({ message: "Only Admin can do this!" });
  });

  // Verified Middleware
export const verifiedMiddleware = asyncHandler(async (req, res, next) => {
    if (req.user && req.user.isVerified) {
      // If user is creator, move to the next Middleware/Controller
      next();
      return;
    }
    // If not creator, send 403 Forbidden --> terminate the request
    res.status(403).json({ message: "Please verify your email address!" });
  });