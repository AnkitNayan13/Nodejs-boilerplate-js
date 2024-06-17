import mongoose from "mongoose";
import validator from "validator";

const userSchema = new mongoose.Schema(
    {
        firstName: {
            type: String,
            trim: true,
            required: [true, "First name is required"],
            maxlength: 50,
        },
        lastName: {
            type: String,
            trim: true,
            maxlength: 50,
        },
        userName: {
            type: String,
            maxlength: 50,
            unique: true,
            trim: true,
        },
        email: {
            type: String,
            required: [true, "email cannot be empty"],
            unique: [true, "email already exists"],
            validate: [validator.isEmail, "Invalid email"],
        },
        emailVerified: {
            type: Date,
            default: null,
        },
        password: {
            type: String,
            minLength: [6, "Password should be atleast 6 characters long"],
        },
    },
    { timestamps: true }
);

export default mongoose.model("User", userSchema);
