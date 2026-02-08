import express from "express";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import bcrypt from "bcrypt";
import cors from "cors";
import { createServer } from "http";
import { Server } from "socket.io";

import { user_db } from "./data.js";
import { activeUsers_db } from "./activeusers.js";
import { authMiddleware } from "./middleware/auth.js";

dotenv.config();

const app = express();
const PORT = 8000;

/* =======================
   MIDDLEWARE
======================= */

app.use(
  cors({
    origin: "http://localhost:5173", // Vite frontend
    credentials: true,               // allow cookies
  })
);

app.use(express.json());
app.use(cookieParser());

let userIdCounter = 1;

/* =======================
   AUTH ROUTES
======================= */

app.post("/signup", async (req, res) => {
  try {
    const { username, password, email } = req.body;

    if (user_db.usernames.has(username))
      return res.status(400).json({ message: "Username exists" });

    if (user_db.emails.has(email))
      return res.status(400).json({ message: "Email exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = userIdCounter++;

    const user = { userId, username, email, password: hashedPassword };

    user_db.users.set(userId, user);
    user_db.usernames.set(username, userId);
    user_db.emails.set(email, userId);

    const token = jwt.sign(
      { userId, username },
      process.env.JWT_SECRET_KEY,
      { expiresIn: "1h" }
    );

    res.cookie("hangout", token, {
      httpOnly: true,
      sameSite: "lax", // required for localhost
    });

    res.status(201).json({ message: "Account created" });
  } catch (err) {
    res.status(500).json({ message: "Signup failed" });
  }
});

app.post("/signin", async (req, res) => {
  const { username, password } = req.body;

  if (!user_db.usernames.has(username))
    return res.status(400).json({ message: "Invalid username" });

  const userId = user_db.usernames.get(username);
  const user = user_db.users.get(userId);

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ message: "Wrong password" });

  const token = jwt.sign(
    { userId, username },
    process.env.JWT_SECRET_KEY,
    { expiresIn: "1h" }
  );

  res.cookie("hangout", token, {
    httpOnly: true,
    sameSite: "lax",
  });

  res.json({ message: "Logged in" });
});

/* =======================
   PROTECTED ROUTES
======================= */

app.post("/rank", authMiddleware, (req, res) => {
  const { stranger_id } = req.body;
  const myid = req.user.userId;

  if (!user_db.rank.has(stranger_id)) {
    user_db.rank.set(stranger_id, {
      count: 1,
      voters: new Set([myid]),
    });
    return res.json({ message: "Rank added", rank: 1 });
  }

  const rankData = user_db.rank.get(stranger_id);

  if (rankData.voters.has(myid))
    return res.status(400).json({ message: "Already ranked" });

  rankData.count++;
  rankData.voters.add(myid);

  res.json({ message: "Rank increased", rank: rankData.count });
});

app.patch("/follow", authMiddleware, (req, res) => {
  const { fromUserId, toUserId } = req.body;

  if (!fromUserId || !toUserId)
    return res.status(400).json({ message: "Missing IDs" });

  if (fromUserId === toUserId)
    return res.status(400).json({ message: "Cannot follow yourself" });

  if (!user_db.users.has(fromUserId) || !user_db.users.has(toUserId))
    return res.status(404).json({ message: "User not found" });

  if (!user_db.follows.has(fromUserId))
    user_db.follows.set(fromUserId, new Set());

  if (!user_db.followers.has(toUserId))
    user_db.followers.set(toUserId, new Set());

  if (user_db.follows.get(fromUserId).has(toUserId))
    return res.status(400).json({ message: "Already following" });

  user_db.follows.get(fromUserId).add(toUserId);
  user_db.followers.get(toUserId).add(fromUserId);

  const isMutual =
    user_db.follows.has(toUserId) &&
    user_db.follows.get(toUserId).has(fromUserId);

  if (isMutual) {
    if (!user_db.friends.has(fromUserId))
      user_db.friends.set(fromUserId, new Set());

    if (!user_db.friends.has(toUserId))
      user_db.friends.set(toUserId, new Set());

    user_db.friends.get(fromUserId).add(toUserId);
    user_db.friends.get(toUserId).add(fromUserId);
  }

  res.json({ success: true, followed: toUserId, mutual: isMutual });
});

/* =======================
   SOCKET.IO
======================= */

const httpServer = createServer(app);

const io = new Server(httpServer, {
  cors: {
    origin: "http://localhost:5173",
    credentials: true,
  },
});

io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error("No token"));

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    socket.user = decoded;
    next();
  } catch {
    next(new Error("Invalid token"));
  }
});

io.on("connection", (socket) => {
  console.log("User connected:", socket.id);
  activeUsers_db.push(socket.id);

  socket.on("message", (msg) => {
    io.emit("message", msg);
  });

  socket.on("disconnect", () => {
    console.log("User disconnected:", socket.id);
  });
});

/* =======================
   START SERVER
======================= */

httpServer.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
