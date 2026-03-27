import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    interests: [{ type: String }],
    bio: { type: String, default: '' },
    avatar: { type: String, default: '' },
    followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    blockedUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    rank: {
        count: { type: Number, default: 0 },
        voters: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
    },
    lastSeen: { type: Date, default: Date.now },
    isOnline: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});
export const otpStore = new Map();

// Index for matching algorithm
userSchema.index({ 'rank.count': -1 });
userSchema.index({ interests: 1 });

const postSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    content: { type: String, required: true },
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    dislikes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    likeCount: { type: Number, default: 0 },
    dislikeCount: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
});

postSchema.index({ userId: 1, createdAt: -1 });

const commentSchema = new mongoose.Schema({
    postId: { type: mongoose.Schema.Types.ObjectId, ref: 'Post', required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    content: { type: String, required: true },
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    createdAt: { type: Date, default: Date.now }
});

const chatSchema = new mongoose.Schema({
    users: [
        { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true }
    ],
    messages: {
        type: Object,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

const notificationSchema = new mongoose.Schema({
    recipientId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    senderId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    type: {
        type: String,
        enum: [
            'follow', 'unfollow', 'like_post', 'dislike_post',
            'comment', 'rank_up', 'rank_down', 'friend_added',
            'post_by_following', 'like_comment'
        ],
        required: true
    },
    referenceId: {
        type: mongoose.Schema.Types.ObjectId,
        default: null
    },
    referenceModel: {
        type: String,
        enum: ['Post', 'Comment', 'User', null],
        default: null
    },
    message: { type: String, required: true },
    isRead: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

notificationSchema.index({ recipientId: 1, createdAt: -1 });
notificationSchema.index({ recipientId: 1, isRead: 1 });

const matchHistorySchema = new mongoose.Schema({
    users: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    matchType: {
        type: String,
        enum: ['interest', 'rank', 'random'],
        default: 'random'
    },
    matchScore: { type: Number, default: 0 },
    commonInterests: [{ type: String }],
    createdAt: { type: Date, default: Date.now }
});

matchHistorySchema.index({ users: 1, createdAt: -1 });

export const User = mongoose.model('User', userSchema);
export const Post = mongoose.model('Post', postSchema);
export const Comment = mongoose.model('Comment', commentSchema);
export const Chat = mongoose.model('Chat', chatSchema);
export const Notification = mongoose.model('Notification', notificationSchema);
export const MatchHistory = mongoose.model('MatchHistory', matchHistorySchema);

// In-memory stores
export const activeUsers = new Map();   // userId -> socketId
export const waitingQueue = [];
export const busyUsers = new Set();