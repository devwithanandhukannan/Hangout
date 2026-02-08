import express from 'express';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcrypt';
import cors from 'cors';
import { createServer } from 'http';
import { Server } from 'socket.io';

import { user_db } from './data.js'; // your in-memory DB
import { activeUsers_db } from './activeusers.js'; // array or map
import { authMiddleware } from './middleware/auth.js';

dotenv.config();

const app = express();
const port = process.env.PORT || 8000;

// --- MIDDLEWARE ---
app.use(express.json());
app.use(cookieParser());

// Allow any front-end (adjust origin for credentials)
app.use(cors({
    origin: "http://127.0.0.1:5500", // your front-end
    credentials: true,
    methods: ["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
}));

// --- USER SIGNUP ---
let userIdCounter = 1;

app.post('/signup', async (req, res) => {
    try {
        const { username, password, email } = req.body;

        if (user_db.usernames.has(username)) return res.status(400).json({ message: 'Username exists' });
        if (user_db.emails.has(email)) return res.status(400).json({ message: 'Email exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const userId = userIdCounter++;
        const user = { userId, username, email, password: hashedPassword };

        user_db.users.set(userId, user);
        user_db.usernames.set(username, userId);
        user_db.emails.set(email, userId);

        const token = jwt.sign({ userId, username }, process.env.JWT_SECRET_KEY, { expiresIn: '1h' });

        res.cookie('hangout', token, {
        httpOnly: true,
        sameSite: "lax",  // important
        secure: false     // important for localhost
        })
           .status(201)
           .json({ message: 'Account created', userId });
    } catch (err) {
        res.status(500).json({ message: "Signup error", error: err.message });
    }
});

// --- USER SIGNIN ---
app.post('/signin', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!user_db.usernames.has(username)) return res.status(400).json({ message: 'Invalid username' });

        const userId = user_db.usernames.get(username);
        const user = user_db.users.get(userId);

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ message: 'Wrong password' });

        const token = jwt.sign({ userId, username }, process.env.JWT_SECRET_KEY, { expiresIn: '1h' });

        res.cookie('hangout', token, { httpOnly: true, sameSite: "lax" })
           .json({ message: 'Logged in', userId });
    } catch (err) {
        res.status(500).json({ message: "Signin error", error: err.message });
    }
});

// --- RANK ROUTE ---
app.post('/rank', authMiddleware, (req, res) => {
    const myId = req.user.userId;
    const { stranger_id } = req.body;

    if (!user_db.rank.has(stranger_id)) {
        user_db.rank.set(stranger_id, { count: 1, voters: new Set([myId]) });
        return res.json({ message: "Rank added", rank: 1 });
    }

    const rankData = user_db.rank.get(stranger_id);
    if (rankData.voters.has(myId)) return res.status(400).json({ message: "Already ranked" });

    rankData.count += 1;
    rankData.voters.add(myId);

    res.json({ message: "Rank increased", rank: rankData.count });
});

// --- FOLLOW ROUTE ---
app.patch('/follow', authMiddleware, (req, res) => {
    const myId = req.user.userId;
    const { toUserId } = req.body;

    if (!toUserId) return res.status(400).json({ message: "Missing toUserId" });
    if (myId === toUserId) return res.status(400).json({ message: "Cannot follow yourself" });
    if (!user_db.users.has(toUserId)) return res.status(404).json({ message: "User not found" });

    if (!user_db.follows.has(myId)) user_db.follows.set(myId, new Set());
    if (!user_db.followers.has(toUserId)) user_db.followers.set(toUserId, new Set());

    if (user_db.follows.get(myId).has(toUserId)) return res.status(400).json({ message: "Already following" });

    user_db.follows.get(myId).add(toUserId);
    user_db.followers.get(toUserId).add(myId);

    const isMutual = user_db.follows.has(toUserId) && user_db.follows.get(toUserId).has(myId);

    if (isMutual) {
        if (!user_db.friends.has(myId)) user_db.friends.set(myId, new Set());
        if (!user_db.friends.has(toUserId)) user_db.friends.set(toUserId, new Set());

        user_db.friends.get(myId).add(toUserId);
        user_db.friends.get(toUserId).add(myId);
    }

    // --- Real-time notification if user is online ---
    const targetSocket = activeUsers_db.get(toUserId); // activeUsers_db as Map
    if (targetSocket) {
        targetSocket.emit("notification", {
            from: myId,
            type: "follow",
            message: `${req.user.userName} followed you!`
        });
    }

    res.json({ success: true, followed: toUserId, mutual: isMutual });
});

// --- SOCKET.IO ---
const httpServer = createServer(app);
const io = new Server(httpServer, {
    cors: {
        origin: "http://127.0.0.1:5500",
        methods: ["GET", "POST"],
        credentials: true
    }
});

// Auth middleware for socket.io
io.use((socket, next) => {
    const token = socket.handshake.auth?.token;
    console.log(socket);
    
    if (!token) return next(new Error("No token provided"));

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
        socket.userId = decoded.userId;
        socket.username = decoded.username;

        // save active user
        activeUsers_db.set(decoded.userId, socket);
        next();
    } catch (err) {
        next(new Error("Invalid token"));
    }
});

io.on("connection", (socket) => {
    console.log("User connected:", socket.userId, socket.id);

    socket.on("message", (msg) => {
        console.log("Message received:", msg);
        io.emit("message", msg);
    });

    socket.on("disconnect", () => {
        console.log("User disconnected:", socket.userId);
        activeUsers_db.delete(socket.userId);
    });
});

// --- START SERVER ---
httpServer.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});


