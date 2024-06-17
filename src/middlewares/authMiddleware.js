import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET;

export async function userAuth(req, res, next) {
    const authHeader = req.headers["authorization"];

    if (!authHeader) return next({ message: "no token found", status: 401 });

    if (!authHeader.startsWith("Bearer"))
        return next({ message: "wrong token format", status: 401 });

    const jwtToken = authHeader.split(" ")[1];

    if (!jwtToken) return next({ message: "no token found", status: 401 });

    try {
        const payload = jwt.verify(jwtToken, JWT_SECRET);
        req.user = {
            id: payload.userId,
        };
        next();
    } catch (error) {
        next({ message: "token expired", status: 401 });
    }
}
