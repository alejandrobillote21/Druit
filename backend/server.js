import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import connect from "./src/db/connect.js";
import cookieParser from "cookie-parser";
import fs from "node:fs";
import errorHandler from "./src/helpers/errorhandler.js";

dotenv.config();

const port = process.env.PORT || 8000;


const app = express();

// Middleware
app.use(
    cors({
    origin: process.env.CLIENT_URL,
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Error Handler
app.use(errorHandler)

//routes
const routeFiles = fs.readdirSync("./src/routes");

routeFiles.forEach((file) => {
    // use dyanamic import
    import(`./src/routes/${file}`).then((route) => {
        app.use("/api/v1", route.default);
    })
    .catch((err) => {
        console.log("Failed to load route file", err);
    });
});

const server = async () => {
    try {

        await connect();

        app.listen(port, () => {
            console.log(`🏃🏃🏃🏃 ...server is running... ${port}🏃`);
        });
    }   catch (error) {
        console.log("Failed to start server... ❌❌❌", error.message);
        process.exit(1);
    }
};

server();