# Hangout

Hangout is a full-stack real-time social communication platform that combines random video and text chat matchmaking with a complete social networking experience. Users create accounts, define their interests, and get intelligently matched with strangers who share similar passions using a multi-factor scoring algorithm that considers common interests, user rank, and match history. Beyond random matching, the platform supports direct friend-to-friend chat requests, WebRTC-powered video and audio calls, a community feed with posts and comments, a follower/following system with automatic friend detection on mutual follows, a heart-based ranking and leaderboard system, real-time notifications delivered over WebSockets, saved chat history, user search and discovery, avatar uploads to AWS S3, and a fully responsive dark-themed UI built with React and Tailwind CSS — all orchestrated through a Node.js/Express backend with MongoDB persistence and Socket.IO for bidirectional real-time communication.

---

## Documentation

Detailed documentation is available in the `documentation/` folder:

| File | Description |
|------|-------------|
| [01-project-description.md](documentation/01-project-description.md) | Project overview, architecture, and technology stack |
| [02-scope-and-features.md](documentation/02-scope-and-features.md) | Complete feature catalog with 42 functional requirements |
| [03-conclusion-and-requirements.md](documentation/03-conclusion-and-requirements.md) | System requirements summary and conclusion |
| [04-workflow-diagrams.md](documentation/04-workflow-diagrams.md) | Visual workflows for matchmaking, messaging, WebRTC calls, and more |
| [05-future-enhancements.md](documentation/05-future-enhancements.md) | Planned improvements including TURN server, E2E encryption, and scaling |

---

## Step-by-Step Run Instructions (Docker Compose)

### Prerequisites

- **Docker** version 20.10 or higher
- **Docker Compose** version 2.0 or higher
- **Git** installed on your machine
- **(Optional)** AWS account with S3 bucket for avatar uploads

### Step 1: Clone the Repository

```bash
git clone https://github.com/devwithanandhukannan/Hangout.git
cd hangout
```

### Step 2: Review the Project Structure

Ensure your directory looks like this:

```
hangout/
├── backend/
│   ├── server.js
│   ├── model.js
│   ├── middleware/
│   │   └── auth.js
│   ├── package.json
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── ChatHistoryPage.jsx
│   │   │   ├── ChatPage.jsx
│   │   │   ├── DashboardPage.jsx
│   │   │   ├── FeedPage.jsx
│   │   │   ├── ForgotPasswordPage.jsx
│   │   │   ├── LandingPage.jsx
│   │   │   ├── LoginPage.jsx
│   │   │   ├── PostPage.jsx
│   │   │   ├── SettingsPage.jsx
│   │   │   └── SignupPage.jsx
│   │   ├── api.js
│   │   ├── AuthContext.jsx
│   │   ├── SocketContext.jsx
│   │   └── Toast.jsx
│   ├── public/
│   ├── package.json
│   └── Dockerfile
├── documentation/
│   ├── 01-project-description.md
│   ├── 02-scope-and-features.md
│   ├── 03-conclusion-and-requirements.md
│   ├── 04-workflow-diagrams.md
│   └── 05-future-enhancements.md
├── docker-compose.yml
├── .env
└── README.md
```

### Step 3: Create the Environment File

Create a `.env` file in the project root:

```bash
touch .env
```

Add the following content (replace placeholder values):

```env
PORT=8000
JWT_SECRET_KEY=<replace-with-a-strong-random-secret-key>
CLIENT_URL=http://localhost:5173
MONGO_URI=mongodb://hangout-mongodb:27017/hangout
AWS_ACCESS_KEY_ID=<your-aws-access-key-id>
AWS_SECRET_ACCESS_KEY=<your-aws-secret-access-key>
AWS_REGION=<your-aws-region>
AWS_S3_BUCKET=<your-s3-bucket-name>
```

### Step 4: Build and Run with Docker Compose

```bash
docker-compose up --build -d
```

Verify all containers are running:

```bash
docker ps
```

Expected output:

```
CONTAINER ID   IMAGE                                     COMMAND                  CREATED        STATUS          PORTS                                         NAMES
19a7c011e4ca   hangout-frontend                          "docker-entrypoint.s…"   15 hours ago   Up 11 seconds   0.0.0.0:5173->5173/tcp, [::]:5173->5173/tcp   frontend
b0296c8169ac   hangout-backend                           "docker-entrypoint.s…"   15 hours ago   Up 11 seconds   0.0.0.0:8000->8000/tcp, [::]:8000->8000/tcp   backend
6b32c3cf66f5   mongodb/mongodb-community-server:latest   "python3 /usr/local/…"   15 hours ago   Up 11 seconds   27017/tcp                                     hangout-mongodb
```

### Step 5: Open the Application

Navigate to the application in your browser:

```
http://localhost:5173
```

### Step 6: Create an Account and Explore

1. Click **Start** on the landing page
2. Click **Create a Hangout account**
3. Fill in username, email, and password
4. Add interests on the Dashboard
5. Click **Go** to start random matchmaking
6. Open a second browser or incognito window to test with two users simultaneously

### Step 7: Stopping the Application

```bash
# Stop all containers
docker-compose down

# Stop and delete all data (including database)
docker-compose down -v

# Stop, delete data, and remove images
docker-compose down -v --rmi all
```

---

## Key Features at a Glance

| Category | Features |
|----------|----------|
| **Authentication** | Registration, login, JWT cookies, session persistence |
| **Matching** | Interest-based scoring, rank proximity, history penalty, blocked user exclusion |
| **Chat** | Real-time text, typing indicators, saved chat history, direct friend requests |
| **Video/Audio** | WebRTC calls with camera/mic toggles, STUN-based NAT traversal |
| **Social** | Posts, comments, likes, follow/friend system with automatic mutual detection |
| **Discovery** | User search, suggested users by interests, leaderboard |
| **Notifications** | Real-time WebSocket delivery, unread counts, management interface |
| **Profile** | Avatar upload to S3, bio, editable fields, rank hearts |

---

## Architecture Overview

```
┌───────────────────────────────────────────────────────────────────────┐
│ Docker Compose                                                        │
│                                                                       │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │ hangout-frontend (React + Nginx)                               │   │
│  │ Port: 5173                                                     │   │
│  └─────────────────────────────┬──────────────────────────────────┘   │
│                                │ HTTP + WebSocket                     │
│                                ▼                                      │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │ hangout-backend (Node.js + Express + Socket.IO)                │   │
│  │ Port: 8000                                                     │   │
│  │                                                                │   │
│  │ ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │   │
│  │ │ REST API     │  │ Socket.IO    │  │ In-Memory State      │   │   │
│  │ │ (Express)    │  │ (Real-time)  │  │ - activeUsers Map    │   │   │
│  │ │ - Auth       │  │ - Matchmaking│  │ - waitingQueue Array │   │   │
│  │ │ - Posts      │  │ - Messaging  │  │ - busyUsers Set      │   │   │
│  │ │ - Follow     │  │ - Signaling  │  └──────────────────────┘   │   │
│  │ │ - Comments   │  │ - Notifs     │                             │   │
│  │ └──────────────┘  └──────────────┘                             │   │
│  └─────────────────────────────┬──────────────────────────────────┘   │
│                                │ Mongoose ODM                         │
│                                ▼                                      │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │ hangout-mongodb (MongoDB 7)                                    │   │
│  │ Port: 27017                                                    │   │
│  │ Collections: users, posts, comments, chats, notifications,     │   │
│  │              matchhistories                                    │   │
│  └────────────────────────────────────────────────────────────────┘   │
│                                                                       │
│  Network: hangout-net (bridge)                                        │
└───────────────────────────────────────────────────────────────────────┘
```

---

## Matchmaking Algorithm

The platform uses a multi-factor scoring algorithm to find the best available partner:

```
Match Score = (Common Interests × 50)
            + Rank Proximity Bonus (max 30)
            + Combined Rank Bonus (max 20)
            - Recent Match Penalty (30 per match in last 24h)
```

- **Interest Matching** (50 pts per common interest): The most heavily weighted factor
- **Rank Proximity Bonus**: `max(0, 30 - rankDifference × 2)` – prefers users with similar rank
- **Combined Rank Bonus**: `min(20, combinedRank × 2)` – rewards higher-ranked users
- **History Penalty**: -30 per recent match – encourages meeting new people

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| **Port conflicts** | If ports 5173 or 8000 are already in use, modify the port mappings in `docker-compose.yml` |
| **MongoDB connection issues** | Ensure `MONGO_URI` in `.env` uses the service name `hangout-mongodb` as shown |
| **AWS S3 errors** | Avatar uploads require valid AWS credentials. The app will function without them, but avatar features will be disabled |
| **WebSocket failures** | Verify `CLIENT_URL` matches your frontend address and that no firewall blocks WebSocket connections |
| **Video call failures** | Some corporate networks block WebRTC. Try on a different network or use text chat instead |

---

## Technology Stack

| Layer | Technology | Version |
|-------|------------|---------|
| Runtime | Node.js | 18 LTS |
| Framework | Express.js | 4.x |
| Frontend | React | 18.x |
| Styling | Tailwind CSS | 3.x |
| Database | MongoDB | 7.x |
| ODM | Mongoose | 7.x/8.x |
| WebSocket | Socket.IO | 4.x |
| Video | WebRTC (native browser) | N/A |
| Authentication | JSON Web Tokens | 9.x |
| Hashing | bcrypt | 5.x |
| File Upload | Multer + AWS S3 SDK v3 | Latest |
| Container | Docker + Compose | 20.10+ |

