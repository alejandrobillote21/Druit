import express from "express";
import {
  changePassword,
  forgotPassword,
  getUser,
  loginUser,
  logoutUser,
  registerUser,
  resetPassword,
  updateUser,
  userLoginStatus,
  verifyEmail,
  verifyUser,
} from "../controllers/auth/userController.js";
import {
  adminMiddleware,
  creatorMiddleware,
  protect,
} from "../middleware/authMiddleware.js";
import {
  deleteUser,
  getAllUsers,
} from "../controllers/auth/adminController.js";

const router = express.Router();

router.post("/register", registerUser);
router.post("/login", loginUser);
router.get("/logout", logoutUser);
router.get("/user", protect, getUser);
router.patch("/user", protect, updateUser);

// Admin Route
router.delete("/admin/users/:id", protect, adminMiddleware, deleteUser);

// Get All Users
router.get("/admin/users", protect, creatorMiddleware, getAllUsers)

// Login Status
router.get("/login-status", userLoginStatus);

// Email verification
router.post("/verify-email", protect, verifyEmail);

// Verify User ---> Email verification
router.post("/verify-user/:verificationToken", verifyUser);

// Forgot password
router.post("/forgot-password", forgotPassword);

// Reset password
router.post("/reset-password/:resetPasswordToken", resetPassword);

// Change password ---> User must be logged in
router.patch("/change-password", protect, changePassword);

export default router;
