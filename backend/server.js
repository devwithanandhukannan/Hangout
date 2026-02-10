import express from 'express';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcrypt';
import cors from 'cors';
import { createServer } from 'http';
import { Server } from 'socket.io';
import { authMiddleware, socketAuthMiddleware } from './middleware/auth.js';
import { activeUsers, busyUsers, waitingQueue, Chat, Comment, Post, User } from './model.js';
import mongoose from 'mongoose';
import { log } from 'console';
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

//controller

// Increase rank for a user
async function increaseRank(myUserId, targetUserId) {
    const user = await User.findById(targetUserId);
    if (!user) throw { status: 404, message: 'User not found' };

    if (user.rank.voters.includes(myUserId)) {
        throw { status: 400, message: 'You already ranked this user' };
    }

    user.rank.count += 1;
    user.rank.voters.push(myUserId);
    await user.save();

    return user.rank.count;
}

// Follow a user
async function followUser(myUserId, targetUserId) {
    if (myUserId === targetUserId) {
        throw { status: 400, message: 'Cannot follow yourself' };
    }

    const [fromUser, toUser] = await Promise.all([
        User.findById(myUserId),
        User.findById(targetUserId)
    ]);

    if (!fromUser || !toUser) throw { status: 404, message: 'User not found' };

    if (fromUser.following.includes(targetUserId)) {
        throw { status: 400, message: 'Already following' };
    }

    fromUser.following.push(targetUserId);
    toUser.followers.push(myUserId);

    const isMutual = toUser.following.includes(myUserId);
    if (isMutual) {
        fromUser.friends.push(targetUserId);
        toUser.friends.push(myUserId);
    }

    await Promise.all([fromUser.save(), toUser.save()]);

    return { followed: targetUserId, mutual: isMutual };
}



// Routes
app.post('/signup', async (req, res) => {
    try {
        const { username, password, email } = req.body;
        const existingUser = await User.findOne({
            $or: [{ username }, { email }]
        });
        if (existingUser) {
            return res.status(400).json({
                message: existingUser.username === username ? 'Username exists' : 'Email exists'
            });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            username,
            email,
            password: hashedPassword,
        });
        await user.save();
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
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ message: 'Invalid username' });
        }
        const ok = await bcrypt.compare(password, user.password);
        if (!ok) {
            return res.status(401).json({ message: 'Wrong password' });
        }
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

        if (post.userId.toString() !== userId) {
            return res.status(403).json({ message: 'Not authorized' });
        }

        await Comment.deleteMany({ postId });

        await Post.findByIdAndDelete(postId);

        res.status(200).json({ message: 'Post deleted' });
    } catch (error) {
        console.error('Delete post error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

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

app.get('/profile', authMiddleware, async (req, res) => {
    try {
        const userId = req.userId;

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

app.patch('/interests', authMiddleware, async (req, res) => {
    try {
        const { interest } = req.body;
        const user = await User.findById(req.userId)
        if (!user) {
            return res.status(400).json({ message: 'Cannot find user' })
        }
        user.interests = []
        await user.save()
        user.interests.push(interest)
        await user.save()

        res.status(200).json({ interests: user.interests });
    } catch (error) {
        console.error('Get interests error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/interests', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select('interests');
        res.status(200).json({ interests: user.interests });
    } catch (error) {
        console.error('Get interests error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

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

app.get('/posts', authMiddleware, async (req, res) => {
    try {
        const userId = req.userId
        const posts = await Post.find({ userId })
            .populate('userId', 'username')
            .sort({ createdAt: -1 });

        res.status(200).json(posts);
    } catch (error) {
        console.error('Get posts error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/feed', authMiddleware, async (req, res) => {
    try {
        const userObj = await User.findById(req.userId)
                                  .select('following')

        if (!userObj || userObj.following.length === 0) {
            return res.json({ message: 'No posts available' });
        }

        const followingIds = userObj.following.map(u => u._id);
        followingIds.push(req.userId);

        const posts = await Post.find({ userId: { $in: followingIds } })
                                .sort({ createdAt: -1 })
                                .limit(10)

        res.json(posts);
    } catch (error) {
        console.error('Get posts error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.patch('/unfollow', authMiddleware, async (req, res) => {
    try {
        const { unfollow_user_id } = req.body;
        const userID = req.userId;

        const [currentUser, targetUser] = await Promise.all([
            User.findById(userID),
            User.findById(unfollow_user_id)
        ]);

        if (!currentUser || !targetUser) {
            return res.status(404).json({ message: 'User not found' });
        }

        const isFollowing = currentUser.following.some(
            id => id.toString() === unfollow_user_id
        );

        if (!isFollowing) {
            return res.status(400).json({ message: 'You are not following this user' });
        }

        // remove from following
        currentUser.following = currentUser.following.filter(
            id => id.toString() !== unfollow_user_id
        );

        // remove from followers
        targetUser.followers = targetUser.followers.filter(
            id => id.toString() !== userID
        );

        // remove friendship if exists
        currentUser.friends = currentUser.friends.filter(
            id => id.toString() !== unfollow_user_id
        );

        targetUser.friends = targetUser.friends.filter(
            id => id.toString() !== userID
        );

        await Promise.all([currentUser.save(), targetUser.save()]);

        res.json({
            success: true,
            unfollowed: unfollow_user_id
        });

    } catch (error) {
        console.error('Unfollow error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.patch('/remove_follower', authMiddleware, async (req, res) => {
    try {
        const { follower_user_id } = req.body;
        const userID = req.userId;

        const [currentUser, followerUser] = await Promise.all([
            User.findById(userID),
            User.findById(follower_user_id)
        ]);

        if (!currentUser || !followerUser) {
            return res.status(404).json({ message: 'User not found' });
        }

        const isFollower = currentUser.followers.some(
            id => id.toString() === follower_user_id
        );

        if (!isFollower) {
            return res.status(400).json({ message: 'User is not your follower' });
        }

        // remove follower
        currentUser.followers = currentUser.followers.filter(
            id => id.toString() !== follower_user_id
        );

        // remove following from follower side
        followerUser.following = followerUser.following.filter(
            id => id.toString() !== userID
        );

        // remove friendship if exists
        currentUser.friends = currentUser.friends.filter(
            id => id.toString() !== follower_user_id
        );

        followerUser.friends = followerUser.friends.filter(
            id => id.toString() !== userID
        );

        await Promise.all([currentUser.save(), followerUser.save()]);

        res.json({
            success: true,
            removedFollower: follower_user_id
        });

    } catch (error) {
        console.error('Remove follower error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});



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

io.use(socketAuthMiddleware);

io.on("connection", (socket) => {
    console.log("User connected:", socket.userId, socket.id);
    activeUsers.set(socket.userId, socket.id);
    socket.on("getInterests", async () => {
        try {
            const user = await User.findById(socket.userId).select('interests');
            socket.emit("interests", user.interests || []);
        } catch (error) {
            console.error("Get interests socket error:", error);
        }
    });

    socket.on("findChat", async () => {
        if (busyUsers.has(socket.userId)) return;

        try {
            const user = await User.findById(socket.userId).select('interests');
            const userInterests = user.interests || [];

            let matchedPartner = null;
            let matchIndex = -1;

            if (userInterests.length > 0) {
                for (let i = 0; i < waitingQueue.length; i++) {
                    const waitingUser = waitingQueue[i];
                    if (waitingUser.interests && waitingUser.interests.length > 0) {
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

    socket.on("privateMessage", async ({ text, room }) => {
        try {
            const rooms = Array.from(socket.rooms).filter(r => r !== socket.id);
            const targetRoom = room || (rooms.length > 0 ? rooms[0] : null);

            if (!targetRoom) return;

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

            io.to(targetRoom).emit("privateMessage", {
                senderId: socket.userId,
                text,
                timestamp: new Date()
            });
        } catch (error) {
            console.error("Private message error:", error);
        }
    });

    socket.on("follow", async () => {
        try {
            const rooms = Array.from(socket.rooms).filter(r => r !== socket.id);
            const targetRoom = rooms.length > 0 ? rooms[0] : null;
            if (!targetRoom) return;

            const userIds = targetRoom.split("_");
            const receiverId = userIds.find(id => id !== socket.userId);
            if (!receiverId) return;

            await followUser(socket.userId, receiverId);
            console.log("followed", receiverId);

            socket.emit("followed", { partnerId: receiverId });
        } catch (error) {
            console.error("following error:", error);
        }
    });

    socket.on("like", async () => {
        try {
            const rooms = Array.from(socket.rooms).filter(r => r !== socket.id);
            const targetRoom = rooms.length > 0 ? rooms[0] : null;
            if (!targetRoom) return;

            const userIds = targetRoom.split("_");
            const receiverId = userIds.find(id => id !== socket.userId);
            if (!receiverId) return;

            await increaseRank(socket.userId, receiverId);
            console.log("liked", receiverId);

            socket.emit("ranked", { partnerId: receiverId });
        } catch (error) {
            console.error("liking error:", error);
        }
    });


    socket.on("signal", ({ data, room }) => {
        const targetRoom = room || Array.from(socket.rooms).find(r => r !== socket.id);
        if (targetRoom) {
            socket.to(targetRoom).emit("signal", { data });
        }
    });

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

    socket.on("disconnect", () => {
        console.log("User disconnected:", socket.userId);

        activeUsers.delete(socket.userId);
        busyUsers.delete(socket.userId);
        const index = waitingQueue.findIndex(user => user.userId === socket.userId);
        if (index !== -1) {
            waitingQueue.splice(index, 1);
        }
        const rooms = Array.from(socket.rooms).filter(r => r !== socket.id);
        rooms.forEach(room => {
            socket.to(room).emit("partnerDisconnected");
        });
    });
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Something went wrong!' });
});

httpServer.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});