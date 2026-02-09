import jwt from "jsonwebtoken";
import cookie from "cookie";

export function authMiddleware(req, res, next) {
  const token = req.cookies?.hangout;
  if (!token) return res.status(401).json({ message: "No token" });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET_KEY);
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
}


export const socketAuthMiddleware = (socket, next) => {
  try {
    const cookies = cookie.parse(socket.handshake.headers.cookie || "");
    const token = cookies.hangout;
    if (!token) return next(new Error("Invalid token"));

    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);

    socket.userId = decoded.userId;
    socket.userName = decoded.username;

    next();
  } catch (err) {
    next(new Error("Invalid or expired token"));
  }
};
