import express from 'express';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcrypt';
import { activeUsers, user_db, busyUsers, waitingQueue } from './data.js';
import { createServer } from 'http';
import { Server } from 'socket.io';
import { authMiddleware } from './middleware/auth.js';
import { socketAuthMiddleware } from './middleware/auth.js';
import cors from 'cors';


dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const CLIENT_URL = process.env.CLIENT_URL
app.use(express.json());
app.use(cookieParser());

app.use(cors({
    origin: [CLIENT_URL, 'http://localhost:5173', 'http://localhost:5500'],
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
}));

let userIdCounter = 1;

app.post('/signup', async (req, res) => {
   try {
     const { username, password, email } = req.body;
    if (user_db.usernames.has(username)) {
        return res.status(400).json({ message: 'Username exists' });
    } if (user_db.emails.has(email)) {
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
    res.cookie('hangout', token, {
    httpOnly: true,
    sameSite: 'lax',   
    secure: false      
  })
        .status(201)
        .json({ message: 'Account created' });
   } catch (error) {
    return res.status(400).send(err)
   }
});

app.post('/rank', authMiddleware, (req, res) => {
    const { stranger_id } = req.body;
    const myid = req.user.id;
    if (!user_db.rank.has(stranger_id)) {
        user_db.rank.set(stranger_id, {
            count: 1,
            voters: new Set([myid])
        });

        return res.json({ message: 'Rank added', rank: 1 });
    }
    const rankData = user_db.rank.get(stranger_id);
    if (rankData.voters.has(myid)) {
        return res.status(400).json({ message: 'You already ranked this user' });
    }
    rankData.count += 1;
    rankData.voters.add(myid);
    res.json({ message: 'Rank increased', rank: rankData.count });
});

app.patch('/follow', authMiddleware, (req, res) => {
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
        user_db.follows.has(toUserId) && user_db.follows.get(toUserId).has(fromUserId);
    if (isMutual) {
        if (!user_db.friends.has(fromUserId)) {
            user_db.friends.set(fromUserId, new Set());
        } if (!user_db.friends.has(toUserId)) {
            user_db.friends.set(toUserId, new Set());
        }
        user_db.friends.get(fromUserId).add(toUserId);
        user_db.friends.get(toUserId).add(fromUserId);
    }
    console.log(user_db)

    res.json({
        success: true,
        followed: toUserId,
        mutual: isMutual,
    });
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
    res.cookie('hangout', token, {
    httpOnly: true,
    sameSite: 'lax',   
    secure: false     
  }).json({ message: 'Logged in' });
});

//get current user user_id;

// socket connection
const httpServer = createServer(app);

const io = new Server(httpServer, {
    cors: {
       origin: [CLIENT_URL, 'http://localhost:5173', 'http://localhost:5500'],
        methods: ["GET", "POST"],
        credentials: true
    },
    pingInterval:10000,
    pingTimeout:5000,
    maxHttpBufferSize:1e6
});

//before create conn.
io.use(socketAuthMiddleware)


function leaveChat(socket, partnerId) {
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

io.on("connection", (socket) => {
  console.log("user connected", socket.id);

  // add to active users
  activeUsers.set(socket.userId, socket.id);
  console.log("Active Users:", Array.from(activeUsers.keys()));

  // ----------------- Random chat matchmaking -----------------
  socket.on("findRandomChat", () => {
    if (busyUsers.has(socket.userId)) return; // already in chat

    if (waitingQueue.length > 0) {
      const partnerId = waitingQueue.shift(); // get first waiting user
      const room = [socket.userId, partnerId].sort().join("_");

      // mark both busy
      busyUsers.add(socket.userId);
      busyUsers.add(partnerId);

      // join room
      socket.join(room);
      const partnerSocketId = activeUsers.get(partnerId);
      if (partnerSocketId) {
        io.sockets.sockets.get(partnerSocketId)?.join(room);
        io.to(partnerSocketId).emit("chatStarted", { room, partnerId: socket.userId });
      }

      socket.emit("chatStarted", { room, partnerId });
    } else {
      // no one waiting, add to queue
      waitingQueue.push(socket.userId);
      socket.emit("waitingForPartner");
    }
  });

  // ----------------- Private messages -----------------
  socket.on("privateMessage", ({ text }) => {
    const rooms = Array.from(socket.rooms).filter(r => r !== socket.id);
    rooms.forEach(room => {
      io.to(room).emit("privateMessage", {
        senderId: socket.userId,
        text
      });
    });
  });

  // ----------------- WebRTC signaling -----------------
  socket.on("signal", ({ data }) => {
    // send to all other users in the room(s)
    const rooms = Array.from(socket.rooms).filter(r => r !== socket.id);
    rooms.forEach(room => {
      socket.to(room).emit("signal", { data });
    });
  });

  // ----------------- Leave chat -----------------
  function leaveChat(socket, partnerId) {
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

  socket.on("leaveChat", ({ partnerId }) => {
    leaveChat(socket, partnerId);
  });

  // ----------------- Disconnect -----------------
  socket.on("disconnect", () => {
    activeUsers.delete(socket.userId);
    busyUsers.delete(socket.userId);

    const idx = waitingQueue.indexOf(socket.userId);
    if (idx !== -1) waitingQueue.splice(idx, 1);
  });
});


httpServer.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});