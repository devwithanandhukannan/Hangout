import mongoose from 'mongoose';

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

export const User = mongoose.model('User', userSchema);
export const Post = mongoose.model('Post', postSchema);
export const Comment = mongoose.model('Comment', commentSchema);
export const Chat = mongoose.model('Chat', chatSchema);

// In-memory data
export const activeUsers = new Map(); // userId => socketId
export const waitingQueue = []; // { userId, interests, socketId }
export const busyUsers = new Set(); // userIds currently in chat

