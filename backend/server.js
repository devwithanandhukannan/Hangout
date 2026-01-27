import express from 'express';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcrypt';
import { user_db } from './data.js';
import { log } from 'node:console';

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(cookieParser());

let userIdCounter = 1;

app.post('/signup', async (req, res) => {
    const { username, password, email } = req.body;

    if (user_db.usernames.has(username)) {
        return res.status(400).json({ message: 'Username exists' });
    }
    if (user_db.emails.has(email)) {
        return res.status(400).json({ message: 'Email exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = userIdCounter++;

    const user = { userId, username, email, password: hashedPassword };

    user_db.users.set(userId, user);
    user_db.usernames.set(username, userId);
    user_db.emails.set(email, userId);

    const token = jwt.sign(
        { userId, username },
        process.env.JWT_SECRET_KEY,
        { expiresIn: '1h' }
    );
    console.log(user_db)
    res.cookie('hangout', token, { httpOnly: true })
        .status(201)
        .json({ message: 'Account created' });
});

app.post('/signin', async (req, res) => {
    const { username, password } = req.body;

    if (!user_db.usernames.has(username)) {
        return res.status(400).json({ message: 'Invalid username' });
    }

    const userId = user_db.usernames.get(username);
    const user = user_db.users.get(userId);

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) {
        return res.status(401).json({ message: 'Wrong password' });
    }

    const token = jwt.sign(
        { userId, username },
        process.env.JWT_SECRET_KEY,
        { expiresIn: '1h' }
    );
    console.log(user_db)
    res.cookie('hangout', token, { httpOnly: true })
        .json({ message: 'Logged in' });
});

app.patch('/follow', (req, res) => {
    const { fromUserId, toUserId } = req.body;

    if (!fromUserId || !toUserId) {
        return res.status(400).json({ message: 'missing ids' });
    }

    if (fromUserId === toUserId) {
        return res.status(400).json({ message: 'cannot follow yourself' });
    }

    if (!user_db.users.has(fromUserId)) {
        return res.status(404).json({ message: 'from user does not exist' });
    }

    if (!user_db.users.has(toUserId)) {
        return res.status(404).json({ message: 'to user does not exist' });
    }

    if (!user_db.follows.has(fromUserId)) {
        user_db.follows.set(fromUserId, new Set());
    }

    if (!user_db.followers.has(toUserId)) {
        user_db.followers.set(toUserId, new Set());
    }


    if (user_db.follows.get(fromUserId).has(toUserId)) {
        return res.status(400).json({ message: 'Already following' });
    }

    user_db.follows.get(fromUserId).add(toUserId);
    user_db.followers.get(toUserId).add(fromUserId);

    const isMutual =
        user_db.follows.has(toUserId) &&
        user_db.follows.get(toUserId).has(fromUserId);

    if (isMutual) {
        if (!user_db.friends.has(fromUserId)) {
            user_db.friends.set(fromUserId, new Set());
        }
        if (!user_db.friends.has(toUserId)) {
            user_db.friends.set(toUserId, new Set());
        }

        user_db.friends.get(fromUserId).add(toUserId);
        user_db.friends.get(toUserId).add(fromUserId);
    }

    res.json({
        success: true,
        followed: toUserId,
        mutual: isMutual,
    });
});


app.listen(port, () => {
    console.log(`Server running on ${port}`);
});
