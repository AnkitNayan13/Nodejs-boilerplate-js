import {
    checkEmail,
    generateJWTToken,
    getUserByEmail,
    hashedPassword,
    matchPassword,
    uniqueUserName,
} from "../utils/user.js";
import User from "../schemas/userSchema.js";
import validator from "validator";

export const register = async (req, res, next) => {
    try {
        const { firstName, lastName, userName, email, password } = req.body;

        if (!firstName) {
            next({ message: "First Name is required", status: 400 });
            return;
        }

        if (!email) {
            next({ message: "Email is required", status: 400 });
            return;
        }

        const isValidEmail = validator.isEmail(email);

        if (!isValidEmail) {
            next({ message: "Invalid email", status: 400 });
            return;
        }

        if (userName) {
            const isUserNameUnique = await uniqueUserName(userName);
            if (!isUserNameUnique) {
                next({ message: "Username already exists", status: 400 });
                return;
            }
        }

        if (!password) {
            next({ message: "Password is required", status: 400 });
            return;
        }

        const isEmailTaken = await checkEmail(email);
        if (!isEmailTaken) {
            next({ message: "Email already exists", status: 400 });
            return;
        }

        const userHashedPassword = await hashedPassword(password);

        const user = new User({
            firstName,
            lastName,
            userName,
            email,
            password: userHashedPassword,
        });

        await user.save();

        res.status(201).json({
            message: "User created successfully",
            success: true,
            user,
        });
    } catch (error) {
        next(error);
    }
};

export const login = async (req, res, next) => {
    try {
        const { email, password } = req.body;
        if (!email) {
            next({ message: "Email is required", status: 400 });
            return;
        }
        if (!password) {
            next({ message: "Password is required", status: 400 });
            return;
        }
        const user = await getUserByEmail(email);
        if (!user) {
            next({ message: "Invalid email or password", status: 401 });
            return;
        }

        // OAuth user
        if (!user.password) {
            next({ message: "Invalid email or password", status: 401 });
            return;
        }

        const isMatch = await matchPassword(password, user.password);
        if (!isMatch) {
            next({ message: "Invalid email or password", status: 401 });
            return;
        }

        const token = generateJWTToken(user._id);

        res.status(200).json({
            message: "User logged in successfully",
            success: true,
            token,
            user,
        });
    } catch (error) {
        next(error);
    }
};
