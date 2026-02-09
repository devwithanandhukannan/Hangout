import express from 'express';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcrypt';
import mongoose from 'mongoose';
import cors from 'cors';
import { createServer } from 'http';
import { Server } from 'socket.io';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const CLIENT_URL = process.env.CLIENT_URL;

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: [CLIENT_URL, 'http://localhost:5173', 'http://localhost:5500'],
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Database connection
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error('MongoDB connection error:', err));

// MongoDB Models
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    interests: [{ type: String }],
    followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    rank: {
        count: { type: Number, default: 0 },
        voters: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
    },
    createdAt: { type: Date, default: Date.now }
});

const postSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    content: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const commentSchema = new mongoose.Schema({
    postId: { type: mongoose.Schema.Types.ObjectId, ref: 'Post', required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    content: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const chatSchema = new mongoose.Schema({
    room: { type: String, required: true },
    senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    receiverId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    message: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
    savedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
});

const User = mongoose.model('User', userSchema);
const Post = mongoose.model('Post', postSchema);
const Comment = mongoose.model('Comment', commentSchema);
const Chat = mongoose.model('Chat', chatSchema);

// In-memory data structures for real-time features
const activeUsers = new Map(); // userId => socketId
const waitingQueue = []; // { userId, interests, socketId }
const busyUsers = new Set(); // userIds currently in chat

// Middleware
const authMiddleware = async (req, res, next) => {
    try {
        const token = req.cookies.hangout;
        if (!token) {
            return res.status(401).json({ message: 'No token provided' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
        const user = await User.findById(decoded.userId).select('-password');
        
        if (!user) {
            return res.status(401).json({ message: 'User not found' });
        }

        req.user = user;
        req.userId = decoded.userId;
        next();
    } catch (error) {
        return res.status(401).json({ message: 'Invalid token' });
    }
};

const socketAuthMiddleware = (socket, next) => {
    try {
        const token = socket.handshake.auth.token || socket.handshake.headers.cookie?.split('hangout=')[1]?.split(';')[0];
        
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

// Routes
app.post('/signup', async (req, res) => {
    try {
        const { username, password, email, interests } = req.body;
        
        // Check if user exists
        const existingUser = await User.findOne({ 
            $or: [{ username }, { email }] 
        });
        
        if (existingUser) {
            return res.status(400).json({ 
                message: existingUser.username === username ? 'Username exists' : 'Email exists' 
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const user = new User({
            username,
            email,
            password: hashedPassword,
            interests: interests || []
        });

        await user.save();

        // Generate token
        const token = jwt.sign(
            { userId: user._id, username: user.username },
            process.env.JWT_SECRET_KEY,
            { expiresIn: '1h' }
        );

        res.cookie('hangout', token, {
            httpOnly: true,
            sameSite: 'lax',
            secure: false
        }).status(201).json({ 
            message: 'Account created',
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                interests: user.interests
            }
        });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/signin', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Find user
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ message: 'Invalid username' });
        }

        // Check password
        const ok = await bcrypt.compare(password, user.password);
        if (!ok) {
            return res.status(401).json({ message: 'Wrong password' });
        }

        // Generate token
        const token = jwt.sign(
            { userId: user._id, username: user.username },
            process.env.JWT_SECRET_KEY,
            { expiresIn: '1h' }
        );

        res.cookie('hangout', token, {
            httpOnly: true,
            sameSite: 'lax',
            secure: false
        }).json({ 
            message: 'Logged in',
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                interests: user.interests
            }
        });
    } catch (error) {
        console.error('Signin error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/rank', authMiddleware, async (req, res) => {
    try {
        const { stranger_id } = req.body;
        const myid = req.userId;

        const user = await User.findById(stranger_id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Check if already voted
        if (user.rank.voters.includes(myid)) {
            return res.status(400).json({ message: 'You already ranked this user' });
        }

        // Update rank
        user.rank.count += 1;
        user.rank.voters.push(myid);
        await user.save();

        res.json({ 
            message: 'Rank increased', 
            rank: user.rank.count 
        });
    } catch (error) {
        console.error('Rank error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.patch('/follow', authMiddleware, async (req, res) => {
    try {
        const { toUserId } = req.body;
        const fromUserId = req.userId;

        if (!toUserId) {
            return res.status(400).json({ message: 'Missing user ID' });
        }

        if (fromUserId === toUserId) {
            return res.status(400).json({ message: 'Cannot follow yourself' });
        }

        const [fromUser, toUser] = await Promise.all([
            User.findById(fromUserId),
            User.findById(toUserId)
        ]);

        if (!fromUser || !toUser) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Check if already following
        if (fromUser.following.includes(toUserId)) {
            return res.status(400).json({ message: 'Already following' });
        }

        // Update following/followers
        fromUser.following.push(toUserId);
        toUser.followers.push(fromUserId);

        // Check if mutual follow (friends)
        const isMutual = toUser.following.includes(fromUserId);
        if (isMutual) {
            fromUser.friends.push(toUserId);
            toUser.friends.push(fromUserId);
        }

        await Promise.all([fromUser.save(), toUser.save()]);

        res.json({
            success: true,
            followed: toUserId,
            mutual: isMutual
        });
    } catch (error) {
        console.error('Follow error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Post routes
app.post('/post', authMiddleware, async (req, res) => {
    try {
        const { content } = req.body;
        const userId = req.userId;

        const post = new Post({
            userId,
            content
        });

        await post.save();

        res.status(201).json({
            message: 'Post created',
            post: {
                id: post._id,
                content: post.content,
                createdAt: post.createdAt
            }
        });
    } catch (error) {
        console.error('Post error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/delete-post/:postId', authMiddleware, async (req, res) => {
    try {
        const { postId } = req.params;
        const userId = req.userId;

        const post = await Post.findById(postId);
        if (!post) {
            return res.status(404).json({ message: 'Post not found' });
        }

        // Check if user owns the post
        if (post.userId.toString() !== userId) {
            return res.status(403).json({ message: 'Not authorized' });
        }

        // Delete associated comments first
        await Comment.deleteMany({ postId });

        // Delete post
        await Post.findByIdAndDelete(postId);

        res.status(200).json({ message: 'Post deleted' });
    } catch (error) {
        console.error('Delete post error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Comment routes
app.post('/comment', authMiddleware, async (req, res) => {
    try {
        const { postId, content } = req.body;
        const userId = req.userId;

        const post = await Post.findById(postId);
        if (!post) {
            return res.status(404).json({ message: 'Post not found' });
        }

        const comment = new Comment({
            postId,
            userId,
            content
        });

        await comment.save();

        res.status(201).json({
            message: 'Comment added',
            comment: {
                id: comment._id,
                content: comment.content,
                createdAt: comment.createdAt
            }
        });
    } catch (error) {
        console.error('Comment error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/delete-comment/:commentId', authMiddleware, async (req, res) => {
    try {
        const { commentId } = req.params;
        const userId = req.userId;

        const comment = await Comment.findById(commentId);
        if (!comment) {
            return res.status(404).json({ message: 'Comment not found' });
        }

        // Check if user owns the comment
        if (comment.userId.toString() !== userId) {
            return res.status(403).json({ message: 'Not authorized' });
        }

        await Comment.findByIdAndDelete(commentId);

        res.status(200).json({ message: 'Comment deleted' });
    } catch (error) {
        console.error('Delete comment error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/comments/:postId', authMiddleware, async (req, res) => {
    try {
        const { postId } = req.params;

        const comments = await Comment.find({ postId })
            .populate('userId', 'username')
            .sort({ createdAt: -1 });

        res.status(200).json(comments);
    } catch (error) {
        console.error('Get comments error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get user profile
app.get('/profile/:userId?', authMiddleware, async (req, res) => {
    try {
        const userId = req.params.userId || req.userId;
        
        const user = await User.findById(userId)
            .select('-password')
            .populate('followers following friends', 'username');

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.status(200).json(user);
    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Save chat message
app.post('/save-chat', authMiddleware, async (req, res) => {
    try {
        const { room, senderId, receiverId, message } = req.body;
        const userId = req.userId;

        const chat = new Chat({
            room,
            senderId,
            receiverId,
            message,
            savedBy: [userId]
        });

        await chat.save();

        res.status(201).json({ 
            message: 'Chat saved',
            chatId: chat._id
        });
    } catch (error) {
        console.error('Save chat error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get saved chats
app.get('/saved-chats', authMiddleware, async (req, res) => {
    try {
        const userId = req.userId;

        const savedChats = await Chat.find({ savedBy: userId })
            .populate('senderId receiverId', 'username')
            .sort({ timestamp: -1 });

        res.status(200).json(savedChats);
    } catch (error) {
        console.error('Get saved chats error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get user interests
app.get('/interests', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select('interests');
        res.status(200).json({ interests: user.interests });
    } catch (error) {
        console.error('Get interests error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Update interests
app.patch('/interests', authMiddleware, async (req, res) => {
    try {
        const { interests } = req.body;
        
        await User.findByIdAndUpdate(req.userId, { interests });
        
        res.status(200).json({ message: 'Interests updated' });
    } catch (error) {
        console.error('Update interests error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get posts by user
app.get('/posts/:userId?', authMiddleware, async (req, res) => {
    try {
        const userId = req.params.userId || req.userId;
        
        const posts = await Post.find({ userId })
            .populate('userId', 'username')
            .sort({ createdAt: -1 });

        res.status(200).json(posts);
    } catch (error) {
        console.error('Get posts error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Socket.io setup
const httpServer = createServer(app);
const io = new Server(httpServer, {
    cors: {
        origin: [CLIENT_URL, 'http://localhost:5173', 'http://localhost:5500'],
        methods: ["GET", "POST"],
        credentials: true
    },
    pingInterval: 10000,
    pingTimeout: 5000,
    maxHttpBufferSize: 1e6
});

// Socket middleware
io.use(socketAuthMiddleware);

// Socket connection handling
io.on("connection", (socket) => {
    console.log("User connected:", socket.userId, socket.id);

    // Add to active users
    activeUsers.set(socket.userId, socket.id);

    // Get user interests
    socket.on("getInterests", async () => {
        try {
            const user = await User.findById(socket.userId).select('interests');
            socket.emit("interests", user.interests || []);
        } catch (error) {
            console.error("Get interests socket error:", error);
        }
    });

    // Find chat partner based on interests
    socket.on("findChat", async () => {
        if (busyUsers.has(socket.userId)) return;

        try {
            // Get current user's interests
            const user = await User.findById(socket.userId).select('interests');
            const userInterests = user.interests || [];

            let matchedPartner = null;
            let matchIndex = -1;

            if (userInterests.length > 0) {
                // Try to match with someone with similar interests
                for (let i = 0; i < waitingQueue.length; i++) {
                    const waitingUser = waitingQueue[i];
                    if (waitingUser.interests && waitingUser.interests.length > 0) {
                        // Check for common interests
                        const commonInterests = userInterests.filter(interest => 
                            waitingUser.interests.includes(interest)
                        );
                        
                        if (commonInterests.length > 0) {
                            matchedPartner = waitingUser;
                            matchIndex = i;
                            break;
                        }
                    }
                }
            }

            if (matchedPartner) {
                // Found match with similar interests
                waitingQueue.splice(matchIndex, 1);
                
                const room = [socket.userId, matchedPartner.userId].sort().join("_");
                
                busyUsers.add(socket.userId);
                busyUsers.add(matchedPartner.userId);

                socket.join(room);
                const partnerSocketId = activeUsers.get(matchedPartner.userId);
                
                if (partnerSocketId) {
                    io.sockets.sockets.get(partnerSocketId)?.join(room);
                    io.to(partnerSocketId).emit("chatStarted", { 
                        room, 
                        partnerId: socket.userId,
                        matchType: 'interest'
                    });
                }

                socket.emit("chatStarted", { 
                    room, 
                    partnerId: matchedPartner.userId,
                    matchType: 'interest'
                });
            } else if (waitingQueue.length > 0) {
                // No interest match, connect randomly
                const partner = waitingQueue.shift();
                const room = [socket.userId, partner.userId].sort().join("_");

                busyUsers.add(socket.userId);
                busyUsers.add(partner.userId);

                socket.join(room);
                const partnerSocketId = activeUsers.get(partner.userId);
                
                if (partnerSocketId) {
                    io.sockets.sockets.get(partnerSocketId)?.join(room);
                    io.to(partnerSocketId).emit("chatStarted", { 
                        room, 
                        partnerId: socket.userId,
                        matchType: 'random'
                    });
                }

                socket.emit("chatStarted", { 
                    room, 
                    partnerId: partner.userId,
                    matchType: 'random'
                });
            } else {
                // No one waiting, add to queue with interests
                waitingQueue.push({
                    userId: socket.userId,
                    interests: userInterests,
                    socketId: socket.id
                });
                socket.emit("waitingForPartner");
            }
        } catch (error) {
            console.error("Find chat error:", error);
            socket.emit("error", { message: "Failed to find chat partner" });
        }
    });

    // Private message handling
    socket.on("privateMessage", async ({ text, room }) => {
        try {
            const rooms = Array.from(socket.rooms).filter(r => r !== socket.id);
            const targetRoom = room || (rooms.length > 0 ? rooms[0] : null);
            
            if (!targetRoom) return;

            // Save message to database if needed
            const userIds = targetRoom.split("_");
            const receiverId = userIds.find(id => id !== socket.userId);
            
            if (receiverId) {
                const chat = new Chat({
                    room: targetRoom,
                    senderId: socket.userId,
                    receiverId,
                    message: text
                });
                await chat.save();
            }

            // Broadcast to room
            io.to(targetRoom).emit("privateMessage", {
                senderId: socket.userId,
                text,
                timestamp: new Date()
            });
        } catch (error) {
            console.error("Private message error:", error);
        }
    });

    // Save chat during conversation
    socket.on("saveChatMessage", async ({ messageId }) => {
        try {
            await Chat.findByIdAndUpdate(messageId, {
                $addToSet: { savedBy: socket.userId }
            });
            socket.emit("chatSaved", { messageId });
        } catch (error) {
            console.error("Save chat message error:", error);
        }
    });

    // WebRTC signaling
    socket.on("signal", ({ data, room }) => {
        const targetRoom = room || Array.from(socket.rooms).find(r => r !== socket.id);
        if (targetRoom) {
            socket.to(targetRoom).emit("signal", { data });
        }
    });

    // Leave chat
    socket.on("leaveChat", ({ partnerId }) => {
        if (partnerId) {
            const room = [socket.userId, partnerId].sort().join("_");
            socket.leave(room);
            busyUsers.delete(socket.userId);
            busyUsers.delete(partnerId);

            const partnerSocketId = activeUsers.get(partnerId);
            if (partnerSocketId) {
                io.sockets.sockets.get(partnerSocketId)?.leave(room);
                io.to(partnerSocketId).emit("partnerLeft");
            }
        }
    });

    // Disconnect
    socket.on("disconnect", () => {
        console.log("User disconnected:", socket.userId);
        
        activeUsers.delete(socket.userId);
        busyUsers.delete(socket.userId);

        // Remove from waiting queue
        const index = waitingQueue.findIndex(user => user.userId === socket.userId);
        if (index !== -1) {
            waitingQueue.splice(index, 1);
        }

        // Notify partner if in chat
        const rooms = Array.from(socket.rooms).filter(r => r !== socket.id);
        rooms.forEach(room => {
            socket.to(room).emit("partnerDisconnected");
        });
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Something went wrong!' });
});

// Start server
httpServer.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});