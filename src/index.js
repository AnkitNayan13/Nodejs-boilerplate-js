// Imports
import express from "express";
import dotenv from "dotenv";
import morgan from "morgan";
import cors from "cors";
import helmet from "helmet";

import authRoutes from "./routes/authRoutes.js";
import healthCheckup from "./routes/healthCheckup.js";

import connectDB from "./lib/db.js";

import { errorMiddleware } from "./middlewares/errorMiddleware.js";

// Initializations

const app = express();

// TO load environment file
dotenv.config();

// Database connection
connectDB();

// To accept json data
app.use(express.json());

// to log api calls
app.use(morgan("dev"));

// To allow other origins url to access our backend
app.use(
    cors({
        origin: "*", // add frontend url in production
    })
);

// To set security headers
app.use(helmet());

// ROUTES
app.use("/api/health", healthCheckup);
app.use("/api/auth", authRoutes);

app.get("*", (req, res) => {
    res.status(404).json({
        message: "404 Route not found",
    });
});

// ERROR MIDDLEWARE
app.use(errorMiddleware);

// START SERVER
const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`);
});
