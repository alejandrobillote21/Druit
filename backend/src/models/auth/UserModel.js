import mongoose from "mongoose";
import bcrypt from "bcrypt"

const UserSchema = new mongoose.Schema({
        name: {
            type: String,
            required: [true, "Please provide your name"],
        },

        email: {
            type: String,
            required: [true, "Please enter an email"],
            unique: true,
            trim: true,
            match: [/^([\w-\.]+@([\w-]+\.)+[\w-]{2,4})?$/, "Please add a valid email",],
        },

        password: {
            type: String,
            required: [true, "Please add password"],
        },

        photo: {
            type: String,
            default: "https://avatars.githubusercontent.com/u/19819005?v=4",
        },
    
        bio: {
            type: String,
            default: "I am a new user.",
        },

        role: {
            type: String,
            enum: ["user", "admin", "creator"],
            default: "user",
        },

        isVerified: {
            type: Boolean,
            default: false,
        },
    },
    { timestamps: true, minimize: true }
);

// Hash the password before saving
UserSchema.pre("save", async function(next){
    //Check if the password is not modified
    if(!this.isModified("password")){
        return next();
    }
    // Hash the password ==> Bring in Bcrypt
    // Generate SALT
    const salt = await bcrypt.genSalt(10);
    // Hash the password with the SALT
    const hashedPassword = await bcrypt.hash(this.password, salt);
    // Set the password to the Hashed password
    this.password = hashedPassword;

    // Call the next Middleware
    next();
});

const User = mongoose.model("User", UserSchema);

export default User;
