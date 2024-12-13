import jwt from "jsonwebtoken";

// Use user ID to Generate Token
const generateToken = (id) => {
    // Token must be returned to the client
    return jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: "30d",
    });
};

export default generateToken;