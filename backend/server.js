import express from 'express';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcrypt';
import cors from 'cors';
import { createServer } from 'http';
import { Server } from 'socket.io';
import { authMiddleware, socketAuthMiddleware } from './middleware/auth.js';
import {
    activeUsers, busyUsers, waitingQueue,
    Chat, Comment, Post, User, Notification, MatchHistory
} from './model.js';
import mongoose from 'mongoose';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const CLIENT_URL = process.env.CLIENT_URL;
const IS_PROD = process.env.NODE_ENV === 'production';

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: (origin, callback) => {
        callback(null, true);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Database connection
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error('MongoDB connection error:', err));

// Store io reference globally for helper functions
let ioInstance;

// ─── Cookie helper ───────────────────────────────────────────
// Single source of truth for cookie options.
// When frontend is HTTPS and backend is HTTP behind a proxy,
// OR when both are HTTPS, cookies need secure + sameSite config.
function getCookieOptions() {
    return {
        httpOnly: true,
        // 'none' allows cross-site (HTTPS frontend ↔ HTTP backend via proxy)
        // 'lax' only works same-site
        sameSite: IS_PROD ? 'none' : 'lax',
        secure: IS_PROD,  // true when HTTPS in production
        maxAge: 7 * 24 * 60 * 60 * 1000,
        path: '/',
    };
}

/*
=================================================================
                    HELPER FUNCTIONS
=================================================================
*/

// Send realtime notification
async function sendRealtimeNotification(
    io, recipientId, senderId, type, message,
    referenceId = null, referenceModel = null
) {
    try {
        // Don't notify yourself
        if (recipientId.toString() === senderId.toString()) return null;

        const notification = new Notification({
            recipientId,
            senderId,
            type,
            message,
            referenceId,
            referenceModel
        });
        await notification.save();

        // Populate sender info before sending
        await notification.populate('senderId', 'username avatar');

        // Send via socket if user is online
        const recipientSocketId = activeUsers.get(recipientId.toString());
        if (recipientSocketId) {
            io.to(recipientSocketId).emit('notification', {
                notification: {
                    _id: notification._id,
                    type: notification.type,
                    message: notification.message,
                    sender: notification.senderId,
                    referenceId: notification.referenceId,
                    referenceModel: notification.referenceModel,
                    isRead: false,
                    createdAt: notification.createdAt
                }
            });
        }

        return notification;
    } catch (error) {
        console.error('Send notification error:', error);
    }
}

// Increase rank for a user
async function increaseRank(io, myUserId, targetUserId) {
    if (myUserId.toString() === targetUserId.toString()) {
        throw { status: 400, message: 'Cannot rank yourself' };
    }

    const user = await User.findById(targetUserId);
    if (!user) throw { status: 404, message: 'User not found' };

    const alreadyVoted = user.rank.voters
        .some(id => id.toString() === myUserId.toString());

    let message;

    if (alreadyVoted) {
        user.rank.voters.pull(myUserId);
        user.rank.count = Math.max(0, user.rank.count - 1);
        message = 'unliked';

        await sendRealtimeNotification(
            io, targetUserId, myUserId, 'rank_down',
            'removed their heart from your profile',
            targetUserId, 'User'
        );
    } else {
        user.rank.voters.addToSet(myUserId);
        user.rank.count += 1;
        message = 'liked';

        await sendRealtimeNotification(
            io, targetUserId, myUserId, 'rank_up',
            'gave a heart to your profile ❤️',
            targetUserId, 'User'
        );
    }

    await user.save();

    // Emit rank update to target user in realtime
    const targetSocketId = activeUsers.get(targetUserId.toString());
    if (targetSocketId) {
        io.to(targetSocketId).emit('rankUpdated', {
            newRank: user.rank.count,
            voterId: myUserId,
            action: message
        });
    }

    // Also emit back to the voter
    const voterSocketId = activeUsers.get(myUserId.toString());
    if (voterSocketId) {
        io.to(voterSocketId).emit('rankGiven', {
            targetUserId,
            newRank: user.rank.count,
            action: message
        });
    }

    return {
        count: user.rank.count,
        message
    };
}

// Follow a user with realtime notifications
async function followUser(io, myUserId, targetUserId) {
    if (myUserId.toString() === targetUserId.toString()) {
        throw { status: 400, message: 'Cannot follow yourself' };
    }

    const [fromUser, toUser] = await Promise.all([
        User.findById(myUserId),
        User.findById(targetUserId)
    ]);

    if (!fromUser || !toUser) {
        throw { status: 404, message: 'User not found' };
    }

    // Check if blocked
    if (toUser.blockedUsers?.some(id => id.toString() === myUserId.toString())) {
        throw { status: 403, message: 'You are blocked by this user' };
    }
    if (fromUser.blockedUsers?.some(id => id.toString() === targetUserId.toString())) {
        throw { status: 403, message: 'You have blocked this user' };
    }

    const alreadyFollowing = fromUser.following
        .some(id => id.toString() === targetUserId.toString());

    let message;
    let notificationType;
    let notificationMessage;

    if (alreadyFollowing) {
        fromUser.following.pull(targetUserId);
        toUser.followers.pull(myUserId);
        fromUser.friends.pull(targetUserId);
        toUser.friends.pull(myUserId);

        message = 'Unfollowed successfully';
        notificationType = 'unfollow';
        notificationMessage = 'unfollowed you';
    } else {
        fromUser.following.addToSet(targetUserId);
        toUser.followers.addToSet(myUserId);

        message = 'Followed successfully';
        notificationType = 'follow';
        notificationMessage = 'started following you';

        const isMutual = toUser.following
            .some(id => id.toString() === myUserId.toString());

        if (isMutual) {
            fromUser.friends.addToSet(targetUserId);
            toUser.friends.addToSet(myUserId);

            // Notify both users about becoming friends
            await sendRealtimeNotification(
                io, targetUserId, myUserId, 'friend_added',
                'You are now friends! 🎉',
                myUserId, 'User'
            );
            await sendRealtimeNotification(
                io, myUserId, targetUserId, 'friend_added',
                'You are now friends! 🎉',
                targetUserId, 'User'
            );
        }
    }

    await Promise.all([fromUser.save(), toUser.save()]);

    // Send follow/unfollow notification in realtime
    await sendRealtimeNotification(
        io, targetUserId, myUserId, notificationType,
        notificationMessage, myUserId, 'User'
    );

    // Emit follow status update to both users
    const targetSocketId = activeUsers.get(targetUserId.toString());
    if (targetSocketId) {
        io.to(targetSocketId).emit('followUpdate', {
            userId: myUserId.toString(),
            username: fromUser.username,
            action: alreadyFollowing ? 'unfollowed' : 'followed',
            followersCount: toUser.followers.length,
            isFriend: toUser.friends.some(
                id => id.toString() === myUserId.toString()
            )
        });
    }

    const mySocketId = activeUsers.get(myUserId.toString());
    if (mySocketId) {
        io.to(mySocketId).emit('followUpdate', {
            userId: targetUserId.toString(),
            username: toUser.username,
            action: alreadyFollowing ? 'unfollowed' : 'followed',
            followingCount: fromUser.following.length,
            isFriend: fromUser.friends.some(
                id => id.toString() === targetUserId.toString()
            )
        });
    }

    return {
        targetUserId,
        message,
        isFriend: fromUser.friends.some(
            id => id.toString() === targetUserId.toString()
        )
    };
}

// Like/Dislike a post with realtime notifications
async function togglePostReaction(io, userId, postId, reactionType) {
    const post = await Post.findById(postId);
    if (!post) throw { status: 404, message: 'Post not found' };

    const isLike = reactionType === 'like';
    const reactionArray = isLike ? 'likes' : 'dislikes';
    const oppositeArray = isLike ? 'dislikes' : 'likes';
    const countField = isLike ? 'likeCount' : 'dislikeCount';
    const oppositeCountField = isLike ? 'dislikeCount' : 'likeCount';

    const alreadyReacted = post[reactionArray]
        .some(id => id.toString() === userId.toString());

    // Remove opposite reaction if exists
    const hadOpposite = post[oppositeArray]
        .some(id => id.toString() === userId.toString());

    if (hadOpposite) {
        post[oppositeArray].pull(userId);
        post[oppositeCountField] = Math.max(0, post[oppositeCountField] - 1);
    }

    let action;

    if (alreadyReacted) {
        post[reactionArray].pull(userId);
        post[countField] = Math.max(0, post[countField] - 1);
        action = `un${reactionType}d`;
    } else {
        post[reactionArray].addToSet(userId);
        post[countField] += 1;
        action = `${reactionType}d`;

        // Notify post owner (only for new reactions, not removals)
        if (post.userId.toString() !== userId.toString()) {
            const notifType = isLike ? 'like_post' : 'dislike_post';
            const emoji = isLike ? '👍' : '👎';
            await sendRealtimeNotification(
                io, post.userId, userId, notifType,
                `${action} your post ${emoji}`,
                postId, 'Post'
            );
        }
    }

    await post.save();

    return {
        postId,
        likeCount: post.likeCount,
        dislikeCount: post.dislikeCount,
        action,
        userLiked: post.likes.some(
            id => id.toString() === userId.toString()
        ),
        userDisliked: post.dislikes.some(
            id => id.toString() === userId.toString()
        )
    };
}

// Advanced matching algorithm: rank + interest + history
async function calculateMatchScore(userId1, userId2) {
    const [user1, user2] = await Promise.all([
        User.findById(userId1).select('interests rank blockedUsers'),
        User.findById(userId2).select('interests rank blockedUsers')
    ]);

    if (!user1 || !user2) {
        return { score: 0, commonInterests: [], matchType: 'random' };
    }

    // Check blocked
    if (
        user1.blockedUsers?.some(
            id => id.toString() === userId2.toString()
        ) ||
        user2.blockedUsers?.some(
            id => id.toString() === userId1.toString()
        )
    ) {
        return { score: -1, commonInterests: [], matchType: 'blocked' };
    }

    let score = 0;
    let matchType = 'random';

    // Interest matching (weight: 50 points per common interest)
    const interests1 = user1.interests || [];
    const interests2 = user2.interests || [];
    const commonInterests = interests1.filter(i => interests2.includes(i));

    if (commonInterests.length > 0) {
        score += commonInterests.length * 50;
        matchType = 'interest';
    }

    // Rank-based matching (weight: rank difference penalty)
    const rankDiff = Math.abs(
        (user1.rank?.count || 0) - (user2.rank?.count || 0)
    );
    const rankBonus = Math.max(0, 30 - rankDiff * 2);
    score += rankBonus;

    // Combined rank bonus
    const combinedRank =
        (user1.rank?.count || 0) + (user2.rank?.count || 0);
    score += Math.min(20, combinedRank * 2);

    if (score > 0 && matchType === 'random') {
        matchType = 'rank';
    }

    // Check match history - penalize repeated matches
    const recentMatches = await MatchHistory.countDocuments({
        users: { $all: [userId1, userId2] },
        createdAt: {
            $gte: new Date(Date.now() - 24 * 60 * 60 * 1000)
        }
    });
    score -= recentMatches * 30;

    return { score, commonInterests, matchType };
}

/*
=================================================================
                        AUTH ROUTES
=================================================================
*/

app.post('/signup', async (req, res) => {
    try {
        const { username, password, email } = req.body;

        if (!username || !password || !email) {
            return res.status(400).json({
                message: 'All fields are required'
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                message: 'Password must be at least 6 characters'
            });
        }

        const existingUser = await User.findOne({
            $or: [{ username }, { email }]
        });

        if (existingUser) {
            return res.status(400).json({
                message:
                    existingUser.username === username
                        ? 'Username exists'
                        : 'Email exists'
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            username,
            email,
            password: hashedPassword
        });
        await user.save();

        const token = jwt.sign(
            { userId: user._id, username: user.username },
            process.env.JWT_SECRET_KEY,
            { expiresIn: '7d' }
        );

        res.cookie('hangout', token, getCookieOptions())
            .status(201)
            .json({
                message: 'Account created',
                user: {
                    id: user._id,
                    username: user.username,
                    email: user.email,
                    interests: user.interests,
                    rank: user.rank.count
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
            { expiresIn: '7d' }
        );

        // Update online status
        user.isOnline = true;
        user.lastSeen = new Date();
        await user.save();

        res.cookie('hangout', token, getCookieOptions()).json({
            message: 'Logged in',
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                interests: user.interests,
                rank: user.rank.count
            }
        });
    } catch (error) {
        console.error('Signin error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/logout', authMiddleware, async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.userId, {
            isOnline: false,
            lastSeen: new Date()
        });

        res.cookie('hangout', '', {
            httpOnly: true,
            sameSite: IS_PROD ? 'none' : 'lax',
            secure: IS_PROD,
            expires: new Date(0),
            path: '/'
        });

        res.status(200).json({ message: 'Logout successful' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

/*
=================================================================
                        POST ROUTES
=================================================================
*/

app.post('/post', authMiddleware, async (req, res) => {
    try {
        const { content } = req.body;
        const userId = req.userId;

        if (!content || content.trim().length === 0) {
            return res.status(400).json({
                message: 'Content is required'
            });
        }

        const post = new Post({
            userId,
            content: content.trim()
        });

        await post.save();

        // Notify all followers about new post
        const user = await User.findById(userId).select(
            'followers username'
        );
        if (user && user.followers.length > 0) {
            const notificationPromises = user.followers.map(followerId =>
                sendRealtimeNotification(
                    ioInstance,
                    followerId,
                    userId,
                    'post_by_following',
                    `${user.username} published a new post`,
                    post._id,
                    'Post'
                )
            );
            Promise.all(notificationPromises).catch(err =>
                console.error('Post notification error:', err)
            );
        }

        res.status(201).json({
            message: 'Post created',
            post: {
                id: post._id,
                content: post.content,
                likeCount: 0,
                dislikeCount: 0,
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
        await Notification.deleteMany({
            referenceId: postId,
            referenceModel: 'Post'
        });
        await Post.findByIdAndDelete(postId);

        res.status(200).json({ message: 'Post deleted' });
    } catch (error) {
        console.error('Delete post error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get own posts
app.get('/posts', authMiddleware, async (req, res) => {
    try {
        const userId = req.userId;
        const posts = await Post.find({ userId })
            .populate('userId', 'username avatar rank')
            .sort({ createdAt: -1 });

        const postsWithReaction = posts.map(post => ({
            ...post.toObject(),
            userLiked: post.likes.some(
                id => id.toString() === userId
            ),
            userDisliked: post.dislikes.some(
                id => id.toString() === userId
            )
        }));

        res.status(200).json(postsWithReaction);
    } catch (error) {
        console.error('Get posts error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Like a post
app.patch('/post/:postId/like', authMiddleware, async (req, res) => {
    try {
        const result = await togglePostReaction(
            ioInstance,
            req.userId,
            req.params.postId,
            'like'
        );
        res.status(200).json(result);
    } catch (error) {
        console.error('Like post error:', error);
        res.status(error.status || 500).json({
            message: error.message || 'Server error'
        });
    }
});

// Dislike a post
app.patch('/post/:postId/dislike', authMiddleware, async (req, res) => {
    try {
        const result = await togglePostReaction(
            ioInstance,
            req.userId,
            req.params.postId,
            'dislike'
        );
        res.status(200).json(result);
    } catch (error) {
        console.error('Dislike post error:', error);
        res.status(error.status || 500).json({
            message: error.message || 'Server error'
        });
    }
});

// Get a specific user's posts
app.get('/posts/user/:userId', authMiddleware, async (req, res) => {
    try {
        const targetUserId = req.params.userId;
        const myUserId = req.userId;

        if (targetUserId !== myUserId) {
            const me = await User.findById(myUserId).select('following');
            const isFollowing = me.following.some(
                id => id.toString() === targetUserId
            );

            if (!isFollowing) {
                return res.status(403).json({
                    message:
                        'You need to follow this user to see their posts'
                });
            }
        }

        const posts = await Post.find({ userId: targetUserId })
            .populate('userId', 'username avatar rank')
            .sort({ createdAt: -1 });

        const postsWithReaction = posts.map(post => ({
            ...post.toObject(),
            userLiked: post.likes.some(
                id => id.toString() === myUserId
            ),
            userDisliked: post.dislikes.some(
                id => id.toString() === myUserId
            )
        }));

        res.status(200).json(postsWithReaction);
    } catch (error) {
        console.error('Get user posts error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

/*
=================================================================
                        FEED ROUTE
=================================================================
*/

app.get('/feed', authMiddleware, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;

        const userObj = await User.findById(req.userId).select(
            'following'
        );

        if (!userObj || userObj.following.length === 0) {
            return res.json({
                posts: [],
                message: 'Follow users to see their posts',
                hasMore: false
            });
        }

        const followingIds = [...userObj.following, req.userId];

        const [posts, totalCount] = await Promise.all([
            Post.find({ userId: { $in: followingIds } })
                .populate('userId', 'username avatar rank')
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(limit),
            Post.countDocuments({ userId: { $in: followingIds } })
        ]);

        const postsWithReaction = posts.map(post => ({
            ...post.toObject(),
            userLiked: post.likes.some(
                id => id.toString() === req.userId
            ),
            userDisliked: post.dislikes.some(
                id => id.toString() === req.userId
            )
        }));

        res.json({
            posts: postsWithReaction,
            hasMore: skip + limit < totalCount,
            totalCount,
            page
        });
    } catch (error) {
        console.error('Get feed error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

/*
=================================================================
                        COMMENT ROUTES
=================================================================
*/

app.post('/comment', authMiddleware, async (req, res) => {
    try {
        const { postId, content } = req.body;
        const userId = req.userId;

        if (!content || content.trim().length === 0) {
            return res.status(400).json({
                message: 'Content is required'
            });
        }

        const post = await Post.findById(postId);
        if (!post) {
            return res.status(404).json({ message: 'Post not found' });
        }

        const comment = new Comment({
            postId,
            userId,
            content: content.trim()
        });

        await comment.save();

        // Notify post owner
        if (post.userId.toString() !== userId) {
            await sendRealtimeNotification(
                ioInstance,
                post.userId,
                userId,
                'comment',
                'commented on your post 💬',
                postId,
                'Post'
            );
        }

        await comment.populate('userId', 'username avatar');

        res.status(201).json({
            message: 'Comment added',
            comment: {
                id: comment._id,
                content: comment.content,
                user: comment.userId,
                createdAt: comment.createdAt
            }
        });
    } catch (error) {
        console.error('Comment error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete(
    '/delete-comment/:commentId',
    authMiddleware,
    async (req, res) => {
        try {
            const { commentId } = req.params;
            const userId = req.userId;

            const comment = await Comment.findById(commentId);
            if (!comment) {
                return res.status(404).json({
                    message: 'Comment not found'
                });
            }

            const post = await Post.findById(comment.postId);
            if (
                comment.userId.toString() !== userId &&
                post?.userId.toString() !== userId
            ) {
                return res.status(403).json({
                    message: 'Not authorized'
                });
            }

            await Comment.findByIdAndDelete(commentId);
            res.status(200).json({ message: 'Comment deleted' });
        } catch (error) {
            console.error('Delete comment error:', error);
            res.status(500).json({ message: 'Server error' });
        }
    }
);

app.get('/comments/:postId', authMiddleware, async (req, res) => {
    try {
        const { postId } = req.params;
        const comments = await Comment.find({ postId })
            .populate('userId', 'username avatar')
            .sort({ createdAt: -1 });

        const commentsWithLike = comments.map(c => ({
            ...c.toObject(),
            userLiked: c.likes.some(
                id => id.toString() === req.userId
            ),
            likeCount: c.likes.length
        }));

        res.status(200).json(commentsWithLike);
    } catch (error) {
        console.error('Get comments error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Like a comment
app.patch(
    '/comment/:commentId/like',
    authMiddleware,
    async (req, res) => {
        try {
            const comment = await Comment.findById(
                req.params.commentId
            );
            if (!comment) {
                return res.status(404).json({
                    message: 'Comment not found'
                });
            }

            const alreadyLiked = comment.likes.some(
                id => id.toString() === req.userId
            );

            if (alreadyLiked) {
                comment.likes.pull(req.userId);
            } else {
                comment.likes.addToSet(req.userId);

                if (comment.userId.toString() !== req.userId) {
                    await sendRealtimeNotification(
                        ioInstance,
                        comment.userId,
                        req.userId,
                        'like_comment',
                        'liked your comment',
                        comment.postId,
                        'Post'
                    );
                }
            }

            await comment.save();

            res.status(200).json({
                commentId: comment._id,
                likeCount: comment.likes.length,
                userLiked: !alreadyLiked
            });
        } catch (error) {
            console.error('Like comment error:', error);
            res.status(500).json({ message: 'Server error' });
        }
    }
);

/*
=================================================================
                    PROFILE & USER ROUTES
=================================================================
*/

app.get('/profile', authMiddleware, async (req, res) => {
    try {
        const userId = req.userId;

        const user = await User.findById(userId)
            .select('-password -blockedUsers')
            .populate(
                'followers following friends',
                'username avatar rank isOnline'
            );

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const postCount = await Post.countDocuments({ userId });

        res.status(200).json({
            ...user.toObject(),
            postCount
        });
    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// View another user's profile
app.get('/user/:userId', authMiddleware, async (req, res) => {
    try {
        const targetUserId = req.params.userId;
        const myUserId = req.userId;

        const user = await User.findById(targetUserId)
            .select('-password -blockedUsers -email')
            .populate(
                'followers following friends',
                'username avatar rank isOnline'
            );

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const postCount = await Post.countDocuments({
            userId: targetUserId
        });

        const isFollowing = user.followers.some(
            f => f._id.toString() === myUserId
        );
        const isFollower = user.following.some(
            f => f._id.toString() === myUserId
        );
        const isFriend = user.friends.some(
            f => f._id.toString() === myUserId
        );
        const hasRanked = user.rank.voters.some(
            id => id.toString() === myUserId
        );

        res.status(200).json({
            ...user.toObject(),
            postCount,
            isFollowing,
            isFollower,
            isFriend,
            hasRanked
        });
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.patch('/update_profile', authMiddleware, async (req, res) => {
    try {
        const userId = req.userId;
        const { username, password, email, bio, avatar } = req.body;

        let updateData = {};
        if (username) updateData.username = username;
        if (email) updateData.email = email;
        if (bio !== undefined) updateData.bio = bio;
        if (avatar) updateData.avatar = avatar;

        if (password) {
            if (password.length < 6) {
                return res.status(400).json({
                    message: 'Password must be at least 6 characters'
                });
            }
            updateData.password = await bcrypt.hash(password, 10);
        }

        // Check username/email uniqueness
        if (username || email) {
            const orConditions = [];
            if (username) orConditions.push({ username });
            if (email) orConditions.push({ email });

            const existing = await User.findOne({
                _id: { $ne: userId },
                $or: orConditions
            });
            if (existing) {
                return res.status(400).json({
                    message:
                        existing.username === username
                            ? 'Username taken'
                            : 'Email taken'
                });
            }
        }

        const userobj = await User.findByIdAndUpdate(
            userId,
            updateData,
            { new: true }
        ).select('-password');

        if (!userobj) {
            return res.status(400).json({ message: 'User not found' });
        }

        res.status(200).json({ message: 'Updated', user: userobj });
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Search users
app.get('/search/users', authMiddleware, async (req, res) => {
    try {
        const { q } = req.query;
        if (!q || q.trim().length < 2) {
            return res.status(400).json({
                message: 'Query must be at least 2 characters'
            });
        }

        const users = await User.find({
            _id: { $ne: req.userId },
            username: { $regex: q.trim(), $options: 'i' }
        })
            .select('username avatar rank isOnline')
            .limit(20);

        const me = await User.findById(req.userId).select('following');

        const results = users.map(u => ({
            ...u.toObject(),
            isFollowing: me.following.some(
                id => id.toString() === u._id.toString()
            )
        }));

        res.status(200).json(results);
    } catch (error) {
        console.error('Search error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get leaderboard by rank
app.get('/leaderboard', authMiddleware, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 20;

        const users = await User.find({ 'rank.count': { $gt: 0 } })
            .select('username avatar rank isOnline')
            .sort({ 'rank.count': -1 })
            .limit(limit);

        res.status(200).json(users);
    } catch (error) {
        console.error('Leaderboard error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

/*
=================================================================
                    FOLLOW/UNFOLLOW ROUTES
=================================================================
*/

app.patch('/follow', authMiddleware, async (req, res) => {
    try {
        const { target_user_id } = req.body;
        if (!target_user_id) {
            return res.status(400).json({
                message: 'target_user_id is required'
            });
        }
        const result = await followUser(
            ioInstance,
            req.userId,
            target_user_id
        );
        res.status(200).json(result);
    } catch (error) {
        console.error('Follow error:', error);
        res.status(error.status || 500).json({
            message: error.message || 'Server error'
        });
    }
});

app.patch('/unfollow', authMiddleware, async (req, res) => {
    try {
        const { unfollow_user_id } = req.body;
        if (!unfollow_user_id) {
            return res.status(400).json({
                message: 'unfollow_user_id is required'
            });
        }
        const result = await followUser(
            ioInstance,
            req.userId,
            unfollow_user_id
        );
        res.status(200).json(result);
    } catch (error) {
        console.error('Unfollow error:', error);
        res.status(error.status || 500).json({
            message: error.message || 'Server error'
        });
    }
});

app.patch('/remove_follower', authMiddleware, async (req, res) => {
    try {
        const { follower_user_id } = req.body;
        if (!follower_user_id) {
            return res.status(400).json({
                message: 'follower_user_id is required'
            });
        }
        const result = await followUser(
            ioInstance,
            follower_user_id,
            req.userId
        );
        res.status(200).json(result);
    } catch (error) {
        console.error('Remove follower error:', error);
        res.status(error.status || 500).json({
            message: error.message || 'Server error'
        });
    }
});

// Rank/Heart a user via API
app.patch('/rank/:userId', authMiddleware, async (req, res) => {
    try {
        const result = await increaseRank(
            ioInstance,
            req.userId,
            req.params.userId
        );
        res.status(200).json(result);
    } catch (error) {
        console.error('Rank error:', error);
        res.status(error.status || 500).json({
            message: error.message || 'Server error'
        });
    }
});

// Block a user
app.patch('/block/:userId', authMiddleware, async (req, res) => {
    try {
        const targetUserId = req.params.userId;
        const myUserId = req.userId;

        if (myUserId === targetUserId) {
            return res.status(400).json({
                message: 'Cannot block yourself'
            });
        }

        const me = await User.findById(myUserId);
        if (!me) {
            return res.status(404).json({
                message: 'User not found'
            });
        }

        const isBlocked = me.blockedUsers.some(
            id => id.toString() === targetUserId
        );

        if (isBlocked) {
            me.blockedUsers.pull(targetUserId);
            await me.save();
            return res.status(200).json({ message: 'User unblocked' });
        }

        // Unfollow each other when blocking
        me.blockedUsers.addToSet(targetUserId);
        me.following.pull(targetUserId);
        me.followers.pull(targetUserId);
        me.friends.pull(targetUserId);

        const target = await User.findById(targetUserId);
        if (target) {
            target.following.pull(myUserId);
            target.followers.pull(myUserId);
            target.friends.pull(myUserId);
            await target.save();
        }

        await me.save();
        res.status(200).json({ message: 'User blocked' });
    } catch (error) {
        console.error('Block error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

/*
=================================================================
                    NOTIFICATION ROUTES
=================================================================
*/

app.get('/notifications', authMiddleware, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 30;
        const skip = (page - 1) * limit;

        const [notifications, unreadCount, totalCount] =
            await Promise.all([
                Notification.find({ recipientId: req.userId })
                    .populate('senderId', 'username avatar')
                    .sort({ createdAt: -1 })
                    .skip(skip)
                    .limit(limit),
                Notification.countDocuments({
                    recipientId: req.userId,
                    isRead: false
                }),
                Notification.countDocuments({
                    recipientId: req.userId
                })
            ]);

        res.status(200).json({
            notifications,
            unreadCount,
            hasMore: skip + limit < totalCount,
            page
        });
    } catch (error) {
        console.error('Get notifications error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.patch('/notifications/read', authMiddleware, async (req, res) => {
    try {
        const { notificationIds } = req.body;

        if (notificationIds && notificationIds.length > 0) {
            await Notification.updateMany(
                {
                    _id: { $in: notificationIds },
                    recipientId: req.userId
                },
                { isRead: true }
            );
        } else {
            await Notification.updateMany(
                { recipientId: req.userId, isRead: false },
                { isRead: true }
            );
        }

        res.status(200).json({
            message: 'Notifications marked as read'
        });
    } catch (error) {
        console.error('Mark read error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete(
    '/notifications/clear',
    authMiddleware,
    async (req, res) => {
        try {
            await Notification.deleteMany({
                recipientId: req.userId
            });
            res.status(200).json({
                message: 'Notifications cleared'
            });
        } catch (error) {
            console.error('Clear notifications error:', error);
            res.status(500).json({ message: 'Server error' });
        }
    }
);

app.get(
    '/notifications/unread-count',
    authMiddleware,
    async (req, res) => {
        try {
            const count = await Notification.countDocuments({
                recipientId: req.userId,
                isRead: false
            });
            res.status(200).json({ unreadCount: count });
        } catch (error) {
            console.error('Unread count error:', error);
            res.status(500).json({ message: 'Server error' });
        }
    }
);

/*
=================================================================
                        CHAT ROUTES
=================================================================
*/

app.post('/save-chat', authMiddleware, async (req, res) => {
    try {
        const { partnerId, chatData } = req.body;

        if (!partnerId || !chatData) {
            return res.status(400).json({
                message: 'Missing required data'
            });
        }

        // FIX: use req.userId consistently (not req.user._id)
        const userId = req.userId;

        const newChat = new Chat({
            users: [userId, partnerId],
            messages: chatData
        });

        await newChat.save();

        return res.status(200).json({
            success: true,
            message: 'Chat saved successfully',
            chatId: newChat._id
        });
    } catch (error) {
        console.error('Save chat error:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to save chat'
        });
    }
});

app.delete('/chat/:chatid', authMiddleware, async (req, res) => {
    try {
        const { chatid } = req.params;
        const deletedChat = await Chat.findOneAndDelete({
            _id: chatid,
            users: req.userId
        });

        if (!deletedChat) {
            return res.status(404).json({
                success: false,
                message: 'Chat not found'
            });
        }

        res.status(200).json({
            success: true,
            message: 'Chat deleted successfully'
        });
    } catch (error) {
        console.error('Delete chat error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete chat'
        });
    }
});

app.get('/chats', authMiddleware, async (req, res) => {
    try {
        const userId = req.userId;
        const chats = await Chat.find({ users: userId })
            .populate('users', 'username avatar')
            .sort({ createdAt: -1 });

        res.status(200).json({
            success: true,
            chats
        });
    } catch (error) {
        console.error('Get chats error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch chats'
        });
    }
});

/*
=================================================================
                    INTEREST ROUTES
=================================================================
*/

app.patch('/interests', authMiddleware, async (req, res) => {
    try {
        const { interest } = req.body;
        const user = await User.findById(req.userId);
        if (!user) {
            return res.status(400).json({
                message: 'Cannot find user'
            });
        }

        if (Array.isArray(interest)) {
            user.interests = interest;
        } else {
            user.interests = [interest];
        }

        await user.save();
        res.status(200).json({ interests: user.interests });
    } catch (error) {
        console.error('Update interests error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/interests', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select(
            'interests'
        );
        res.status(200).json({ interests: user.interests });
    } catch (error) {
        console.error('Get interests error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

/*
=================================================================
                    MATCH HISTORY ROUTE
=================================================================
*/

app.get('/match-history', authMiddleware, async (req, res) => {
    try {
        const matches = await MatchHistory.find({
            users: req.userId
        })
            .populate('users', 'username avatar rank')
            .sort({ createdAt: -1 })
            .limit(50);

        res.status(200).json(matches);
    } catch (error) {
        console.error('Match history error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

/*
=================================================================
                    SUGGESTED USERS ROUTE
=================================================================
*/

app.get('/suggested-users', authMiddleware, async (req, res) => {
    try {
        const me = await User.findById(req.userId).select(
            'following interests blockedUsers'
        );

        const excludeIds = [
            req.userId,
            ...me.following.map(id => id.toString()),
            ...(me.blockedUsers || []).map(id => id.toString())
        ];

        let query = { _id: { $nin: excludeIds } };

        if (me.interests.length > 0) {
            query.interests = { $in: me.interests };
        }

        const users = await User.find(query)
            .select('username avatar rank interests isOnline')
            .sort({ 'rank.count': -1 })
            .limit(20);

        const suggestions = users.map(u => {
            const commonInterests = me.interests.filter(i =>
                u.interests.includes(i)
            );
            return {
                ...u.toObject(),
                commonInterests,
                commonCount: commonInterests.length
            };
        });

        suggestions.sort((a, b) => {
            if (b.commonCount !== a.commonCount) {
                return b.commonCount - a.commonCount;
            }
            return (b.rank?.count || 0) - (a.rank?.count || 0);
        });

        res.status(200).json(suggestions);
    } catch (error) {
        console.error('Suggested users error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

/*
=================================================================
                    SOCKET.IO SETUP
=================================================================
*/

const httpServer = createServer(app);
const io = new Server(httpServer, {
    cors: {
        origin: (origin, callback) => {
            callback(null, true);
        },
        methods: ['GET', 'POST'],
        credentials: true
    },
    pingInterval: 10000,
    pingTimeout: 5000,
    maxHttpBufferSize: 1e6,
    transports: ['websocket', 'polling']
});

ioInstance = io;

io.use(socketAuthMiddleware);

io.on('connection', async socket => {
    console.log('User connected:', socket.userId, socket.id);
    activeUsers.set(socket.userId, socket.id);

    // Update online status
    try {
        await User.findByIdAndUpdate(socket.userId, {
            isOnline: true,
            lastSeen: new Date()
        });

        // Notify friends that user is online
        const user = await User.findById(socket.userId).select(
            'friends username'
        );
        if (user && user.friends.length > 0) {
            user.friends.forEach(friendId => {
                const friendSocketId = activeUsers.get(
                    friendId.toString()
                );
                if (friendSocketId) {
                    io.to(friendSocketId).emit('userOnline', {
                        userId: socket.userId,
                        username: user.username
                    });
                }
            });
        }

        // Send unread notification count on connect
        const unreadCount = await Notification.countDocuments({
            recipientId: socket.userId,
            isRead: false
        });
        socket.emit('unreadNotifications', { count: unreadCount });
    } catch (error) {
        console.error('Connection setup error:', error);
    }

    // =====================================================
    //                  SOCKET EVENTS
    // =====================================================

    socket.on('getInterests', async () => {
        try {
            const user = await User.findById(socket.userId).select(
                'interests'
            );
            socket.emit('interests', user?.interests || []);
        } catch (error) {
            console.error('Get interests socket error:', error);
        }
    });

    // ─── Direct Chat: Request ────────────────────────────
    socket.on('directChatRequest', ({ toId, room }) => {
        try {
            const toSocketId = activeUsers.get(toId);

            if (!toSocketId) {
                socket.emit('directChatUserOffline', { toId });
                return;
            }

            io.to(toSocketId).emit('directChatRequest', {
                fromId: socket.userId,
                fromName: socket.username || 'A friend',
                room
            });

            console.log(
                `[Direct] ${socket.userId} → ${toId} room: ${room}`
            );
        } catch (err) {
            console.error('directChatRequest error:', err);
        }
    });

    // ─── Direct Chat: Accept ─────────────────────────────
    socket.on('directChatAccept', ({ toId, room }) => {
        try {
            const toSocketId = activeUsers.get(toId);

            // Join both sockets into the room
            socket.join(room);
            if (toSocketId) {
                io.sockets.sockets.get(toSocketId)?.join(room);
            }

            // Mark both as busy
            busyUsers.add(socket.userId);
            busyUsers.add(toId);

            const chatStartedPayload = {
                room,
                matchType: 'direct',
                commonInterests: [],
                matchScore: 0
            };

            // Tell requester (toId) chat has started
            if (toSocketId) {
                io.to(toSocketId).emit('chatStarted', {
                    ...chatStartedPayload,
                    partnerId: socket.userId
                });
            }

            // Tell accepter (this socket) chat has started
            socket.emit('chatStarted', {
                ...chatStartedPayload,
                partnerId: toId
            });

            console.log(`[Direct] accepted — room: ${room}`);
        } catch (err) {
            console.error('directChatAccept error:', err);
        }
    });

    // ─── Direct Chat: Decline ────────────────────────────
    socket.on('directChatDecline', ({ toId, room }) => {
        try {
            const toSocketId = activeUsers.get(toId);
            if (toSocketId) {
                io.to(toSocketId).emit('directChatDeclined', {
                    byName: socket.username || 'Friend',
                    byId: socket.userId,
                    room
                });
            }
            console.log(
                `[Direct] declined by ${socket.userId}`
            );
        } catch (err) {
            console.error('directChatDecline error:', err);
        }
    });

    // ─── Direct Chat: Cancel ─────────────────────────────
    socket.on('directChatCancel', ({ toId, room }) => {
        try {
            const toSocketId = activeUsers.get(toId);
            if (toSocketId) {
                io.to(toSocketId).emit('directChatCancelled', {
                    byName: socket.username || 'Friend',
                    byId: socket.userId,
                    room
                });
            }
            console.log(
                `[Direct] cancelled by ${socket.userId}`
            );
        } catch (err) {
            console.error('directChatCancel error:', err);
        }
    });

    // ─── Random / Interest / Rank Matching ───────────────
    socket.on('findChat', async () => {
        if (busyUsers.has(socket.userId)) return;

        try {
            const user = await User.findById(socket.userId).select(
                'interests rank blockedUsers'
            );
            const userInterests = user?.interests || [];

            // Calculate scores for all waiting users
            let bestMatch = null;
            let bestScore = -Infinity;
            let bestIndex = -1;
            let bestMatchData = null;

            for (let i = 0; i < waitingQueue.length; i++) {
                const waitingUser = waitingQueue[i];

                // Skip self
                if (waitingUser.userId === socket.userId) continue;

                const matchData = await calculateMatchScore(
                    socket.userId,
                    waitingUser.userId
                );

                // Skip blocked users
                if (matchData.score === -1) continue;

                if (matchData.score > bestScore) {
                    bestScore = matchData.score;
                    bestMatch = waitingUser;
                    bestIndex = i;
                    bestMatchData = matchData;
                }
            }

            if (bestMatch && bestScore >= 0) {
                waitingQueue.splice(bestIndex, 1);

                const room = [socket.userId, bestMatch.userId]
                    .sort()
                    .join('_');

                busyUsers.add(socket.userId);
                busyUsers.add(bestMatch.userId);

                socket.join(room);
                const partnerSocketId = activeUsers.get(
                    bestMatch.userId
                );

                // Save match history
                const matchHistory = new MatchHistory({
                    users: [socket.userId, bestMatch.userId],
                    matchType: bestMatchData.matchType,
                    matchScore: bestScore,
                    commonInterests: bestMatchData.commonInterests
                });
                await matchHistory.save();

                const matchInfo = {
                    room,
                    matchType: bestMatchData.matchType,
                    matchScore: bestScore,
                    commonInterests: bestMatchData.commonInterests
                };

                if (partnerSocketId) {
                    io.sockets.sockets
                        .get(partnerSocketId)
                        ?.join(room);
                    io.to(partnerSocketId).emit('chatStarted', {
                        ...matchInfo,
                        partnerId: socket.userId
                    });
                }

                socket.emit('chatStarted', {
                    ...matchInfo,
                    partnerId: bestMatch.userId
                });
            } else if (waitingQueue.length > 0) {
                // Fallback: pick anyone not blocked
                let fallbackIndex = -1;
                for (let i = 0; i < waitingQueue.length; i++) {
                    if (waitingQueue[i].userId === socket.userId)
                        continue;

                    const check = await calculateMatchScore(
                        socket.userId,
                        waitingQueue[i].userId
                    );
                    if (check.score !== -1) {
                        fallbackIndex = i;
                        break;
                    }
                }

                if (fallbackIndex !== -1) {
                    const partner = waitingQueue.splice(
                        fallbackIndex,
                        1
                    )[0];
                    const room = [socket.userId, partner.userId]
                        .sort()
                        .join('_');

                    busyUsers.add(socket.userId);
                    busyUsers.add(partner.userId);

                    socket.join(room);
                    const partnerSocketId = activeUsers.get(
                        partner.userId
                    );

                    const matchHistory = new MatchHistory({
                        users: [socket.userId, partner.userId],
                        matchType: 'random',
                        matchScore: 0,
                        commonInterests: []
                    });
                    await matchHistory.save();

                    if (partnerSocketId) {
                        io.sockets.sockets
                            .get(partnerSocketId)
                            ?.join(room);
                        io.to(partnerSocketId).emit(
                            'chatStarted',
                            {
                                room,
                                partnerId: socket.userId,
                                matchType: 'random',
                                matchScore: 0,
                                commonInterests: []
                            }
                        );
                    }

                    socket.emit('chatStarted', {
                        room,
                        partnerId: partner.userId,
                        matchType: 'random',
                        matchScore: 0,
                        commonInterests: []
                    });
                } else {
                    // Everyone in queue is blocked
                    const alreadyInQueue = waitingQueue.some(
                        u => u.userId === socket.userId
                    );
                    if (!alreadyInQueue) {
                        waitingQueue.push({
                            userId: socket.userId,
                            interests: userInterests,
                            rank: user?.rank?.count || 0,
                            socketId: socket.id
                        });
                    }
                    socket.emit('waitingForPartner');
                }
            } else {
                // Queue is empty
                const alreadyInQueue = waitingQueue.some(
                    u => u.userId === socket.userId
                );
                if (!alreadyInQueue) {
                    waitingQueue.push({
                        userId: socket.userId,
                        interests: userInterests,
                        rank: user?.rank?.count || 0,
                        socketId: socket.id
                    });
                }
                socket.emit('waitingForPartner');
            }
        } catch (error) {
            console.error('Find chat error:', error);
            socket.emit('error', {
                message: 'Failed to find chat partner'
            });
        }
    });

    // Cancel waiting
    socket.on('cancelWaiting', () => {
        const index = waitingQueue.findIndex(
            user => user.userId === socket.userId
        );
        if (index !== -1) {
            waitingQueue.splice(index, 1);
            socket.emit('waitingCancelled');
        }
    });

    // ─── Private Messaging ───────────────────────────────
    // FIX: use socket.to() instead of io.to() to avoid
    //      sending the message back to the sender
    socket.on('privateMessage', ({ text, room }) => {
        try {
            const rooms = Array.from(socket.rooms).filter(
                r => r !== socket.id
            );
            const targetRoom =
                room || (rooms.length > 0 ? rooms[0] : null);

            if (!targetRoom) return;

            // socket.to() sends to everyone in room EXCEPT sender
            socket.to(targetRoom).emit('privateMessage', {
                senderId: socket.userId,
                text,
                timestamp: new Date()
            });
        } catch (error) {
            console.error('Private message error:', error);
        }
    });

    // Typing indicator
    socket.on('typing', ({ room, isTyping }) => {
        const targetRoom =
            room ||
            Array.from(socket.rooms).find(r => r !== socket.id);
        if (targetRoom) {
            socket.to(targetRoom).emit('partnerTyping', {
                userId: socket.userId,
                isTyping
            });
        }
    });

    // ─── Follow during chat ──────────────────────────────
    socket.on('follow', async () => {
        try {
            const rooms = Array.from(socket.rooms).filter(
                r => r !== socket.id
            );
            const targetRoom =
                rooms.length > 0 ? rooms[0] : null;
            if (!targetRoom) return;

            const userIds = targetRoom.split('_');
            const receiverId = userIds.find(
                id => id !== socket.userId
            );
            if (!receiverId) return;

            const result = await followUser(
                io,
                socket.userId,
                receiverId
            );

            io.to(targetRoom).emit('followStatusUpdate', {
                followerId: socket.userId,
                followedId: receiverId,
                action: result.message.includes('Unfollowed')
                    ? 'unfollowed'
                    : 'followed',
                isFriend: result.isFriend
            });

            socket.emit('followed', {
                partnerId: receiverId,
                message: result.message,
                isFriend: result.isFriend
            });
        } catch (error) {
            console.error('following error:', error);
            socket.emit('followError', {
                message: error.message || 'Failed to follow'
            });
        }
    });

    // Follow a specific user by ID
    socket.on('followUser', async ({ targetUserId }) => {
        try {
            if (!targetUserId) return;
            const result = await followUser(
                io,
                socket.userId,
                targetUserId
            );
            socket.emit('followed', {
                partnerId: targetUserId,
                message: result.message,
                isFriend: result.isFriend
            });
        } catch (error) {
            console.error('followUser error:', error);
            socket.emit('followError', {
                message: error.message || 'Failed to follow'
            });
        }
    });

    // ─── Like/Heart during chat ──────────────────────────
    socket.on('like', async () => {
        try {
            const rooms = Array.from(socket.rooms).filter(
                r => r !== socket.id
            );
            const targetRoom =
                rooms.length > 0 ? rooms[0] : null;
            if (!targetRoom) return;

            const userIds = targetRoom.split('_');
            const receiverId = userIds.find(
                id => id !== socket.userId
            );
            if (!receiverId) return;

            const result = await increaseRank(
                io,
                socket.userId,
                receiverId
            );

            io.to(targetRoom).emit('rankUpdateInChat', {
                userId: receiverId,
                newRank: result.count,
                voterId: socket.userId,
                action: result.message
            });

            socket.emit('ranked', {
                partnerId: receiverId,
                newRank: result.count,
                action: result.message
            });
        } catch (error) {
            console.error('liking error:', error);
            socket.emit('rankError', {
                message: error.message || 'Failed to rank'
            });
        }
    });

    // Like a specific user by ID
    socket.on('likeUser', async ({ targetUserId }) => {
        try {
            if (!targetUserId) return;
            const result = await increaseRank(
                io,
                socket.userId,
                targetUserId
            );
            socket.emit('ranked', {
                partnerId: targetUserId,
                newRank: result.count,
                action: result.message
            });
        } catch (error) {
            console.error('likeUser error:', error);
            socket.emit('rankError', {
                message: error.message || 'Failed to rank'
            });
        }
    });

    // ─── Post reactions via socket ───────────────────────
    socket.on('likePost', async ({ postId }) => {
        try {
            if (!postId) return;
            const result = await togglePostReaction(
                io,
                socket.userId,
                postId,
                'like'
            );
            io.emit('postReactionUpdate', result);
        } catch (error) {
            console.error('likePost socket error:', error);
        }
    });

    socket.on('dislikePost', async ({ postId }) => {
        try {
            if (!postId) return;
            const result = await togglePostReaction(
                io,
                socket.userId,
                postId,
                'dislike'
            );
            io.emit('postReactionUpdate', result);
        } catch (error) {
            console.error('dislikePost socket error:', error);
        }
    });

    // ─── Mark notifications read ─────────────────────────
    socket.on(
        'markNotificationsRead',
        async ({ notificationIds }) => {
            try {
                if (
                    notificationIds &&
                    notificationIds.length > 0
                ) {
                    await Notification.updateMany(
                        {
                            _id: { $in: notificationIds },
                            recipientId: socket.userId
                        },
                        { isRead: true }
                    );
                } else {
                    await Notification.updateMany(
                        {
                            recipientId: socket.userId,
                            isRead: false
                        },
                        { isRead: true }
                    );
                }

                const newCount =
                    await Notification.countDocuments({
                        recipientId: socket.userId,
                        isRead: false
                    });
                socket.emit('unreadNotifications', {
                    count: newCount
                });
            } catch (error) {
                console.error(
                    'Mark notifications read socket error:',
                    error
                );
            }
        }
    );

    // ─── WebRTC Signaling ────────────────────────────────
    socket.on('signal', ({ data, room }) => {
        const targetRoom =
            room ||
            Array.from(socket.rooms).find(r => r !== socket.id);
        if (targetRoom) {
            socket.to(targetRoom).emit('signal', { data });
        }
    });

    // ─── Leave Chat ──────────────────────────────────────
    socket.on('leaveChat', ({ partnerId }) => {
        if (partnerId) {
            const room = [socket.userId, partnerId]
                .sort()
                .join('_');
            socket.leave(room);
            busyUsers.delete(socket.userId);
            busyUsers.delete(partnerId);

            const partnerSocketId = activeUsers.get(partnerId);
            if (partnerSocketId) {
                io.sockets.sockets
                    .get(partnerSocketId)
                    ?.leave(room);
                io.to(partnerSocketId).emit('partnerLeft');
            }
        }
    });

    // ─── Disconnect ──────────────────────────────────────
    socket.on('disconnect', async () => {
        console.log('User disconnected:', socket.userId);

        activeUsers.delete(socket.userId);
        busyUsers.delete(socket.userId);

        const index = waitingQueue.findIndex(
            user => user.userId === socket.userId
        );
        if (index !== -1) {
            waitingQueue.splice(index, 1);
        }

        try {
            // Update online status
            await User.findByIdAndUpdate(socket.userId, {
                isOnline: false,
                lastSeen: new Date()
            });

            // Notify friends that user went offline
            const user = await User.findById(
                socket.userId
            ).select('friends username');
            if (user && user.friends.length > 0) {
                user.friends.forEach(friendId => {
                    const friendSocketId = activeUsers.get(
                        friendId.toString()
                    );
                    if (friendSocketId) {
                        io.to(friendSocketId).emit(
                            'userOffline',
                            {
                                userId: socket.userId,
                                username: user.username,
                                lastSeen: new Date()
                            }
                        );
                    }
                });
            }
        } catch (error) {
            console.error('Disconnect cleanup error:', error);
        }

        // Notify chat partners
        const rooms = Array.from(socket.rooms).filter(
            r => r !== socket.id
        );
        rooms.forEach(room => {
            socket.to(room).emit('partnerDisconnected');
        });
    });
});

/*
=================================================================
                    ERROR HANDLING
=================================================================
*/

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Something went wrong!' });
});

httpServer.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});