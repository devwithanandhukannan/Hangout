import jwt from "jsonwebtoken";
import cookie from "cookie";
import { User } from "../model.js";

export const authMiddleware= async(req, res, next)=> {
  try {
     const token = req.cookies?.hangout;
    
     
    if (!token) return res.status(401).json({ message: "No token" });
     const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
     
        const user = await User.findById(decoded.userId)
        
        if (!user) {
            return res.status(401).json({ message: 'User not found' });
        }

        req.user = user;
        req.userId = decoded.userId;
        next();
    } catch (error) {
        return res.status(401).json({ message: 'Invalid token' });
    }
}


export const socketAuthMiddleware = (socket, next) => {
  try {
    const cookies = cookie.parse(socket.handshake.headers.cookie || "");
    const token = cookies.hangout;
    if (!token) {
            return next(new Error('Authentication error: No token'));
        }
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
        socket.userId = decoded.userId;
        socket.username = decoded.username;
        next();
    } catch (error) {
        next(new Error('Authentication error: Invalid token'));
    }
};

