# Project Description and Introduction

## Overview

Hangout is a real-time social communication platform designed to connect
people across the world through spontaneous conversations. Unlike
traditional social media where users passively scroll through curated
content, Hangout emphasizes live, authentic human interaction by pairing
strangers in real-time video and text chat sessions based on shared
interests, reputation rank, and intelligent matchmaking algorithms.

The platform addresses a growing need for genuine online connection in
an era where social media interactions have become increasingly superficial.
By combining the spontaneity of random chat services like Omegle with the
community features of platforms like Discord and the social graph of
Twitter, Hangout creates a unique space where meaningful connections can
form organically.

## Motivation

Modern social platforms optimize for engagement metrics rather than
genuine human connection. Users spend hours scrolling through feeds but
report feeling more isolated than ever. Hangout takes a fundamentally
different approach: it prioritizes real-time, synchronous communication
where two people share a moment together. The matchmaking algorithm
ensures that conversations are more likely to be enjoyable by connecting
people who share common interests, while the ranking system incentivizes
positive behavior and helps surface the most engaging community members.

## Architecture

Hangout follows a three-tier architecture deployed as containerized
microservices:

```
┌──────────────────────────────────────────────────────────────┐
│                     CLIENT TIER                              │
│  React 18 + Tailwind CSS + React Router v6                   │
│  Socket.IO Client + WebRTC (getUserMedia + RTCPeerConnection)│
└──────────────────┬───────────────────┬───────────────────────┘
                   │ HTTP/REST         │ WebSocket (Socket.IO)
                   │ (JSON + FormData) │ (bidirectional events)
┌──────────────────▼───────────────────▼───────────────────────┐
│                     SERVER TIER                              │
│  Node.js + Express.js                                        │
│  Socket.IO Server (rooms, events, signaling)                 │
│  JWT Authentication (HTTP-only cookies)                      │
│  Multer + AWS S3 (file uploads)                              │
│  Bcrypt (password hashing)                                   │
└──────────────────┬───────────────────────────────────────────┘
                   │ Mongoose ODM
┌──────────────────▼───────────────────────────────────────────┐
│                     DATA TIER                                │
│  MongoDB 7 (document store)                                  │
│  Collections: users, posts, comments, chats,                 │
│               notifications, matchhistories                  │
│  Indexes: rank, interests, recipientId, createdAt            │
└──────────────────────────────────────────────────────────────┘
```

### Frontend Architecture

The frontend is a single-page application built with React 18. State
management is handled through React Context API with two primary
contexts:

- **AuthContext**: manages user authentication state, JWT token
  validation, and session persistence across page reloads.
- **SocketContext**: manages the Socket.IO connection lifecycle,
  exposes event emitters for direct chat requests, handles incoming
  notifications, and tracks unread notification counts.

Page routing is handled by React Router v6 with the following routes:

| Route             | Component           | Auth Required |
| ----------------- | ------------------- | ------------- |
| `/`               | LandingPage         | No            |
| `/login`          | LoginPage           | No            |
| `/signup`         | SignupPage          | No            |
| `/forgot-password`| ForgotPasswordPage  | No            |
| `/dashboard`      | DashboardPage       | Yes           |
| `/chat`           | ChatPage            | Yes           |
| `/chat-history`   | ChatHistoryPage     | Yes           |
| `/feed`           | FeedPage            | Yes           |
| `/post`           | PostPage            | Yes           |
| `/settings`       | SettingsPage        | Yes           |

### Backend Architecture

The backend is a monolithic Node.js server that handles both REST API
endpoints and WebSocket connections through a shared HTTP server. Key
architectural decisions include:

1. **Shared HTTP server**: Express and Socket.IO share the same
   `http.createServer()` instance, allowing WebSocket upgrade on the
   same port.

2. **In-memory state**: Active users, waiting queue, and busy users
   are stored in memory (Maps and Sets) for sub-millisecond access
   during matchmaking. This is acceptable for single-server deployments.

3. **Cookie-based auth**: JWT tokens are stored in HTTP-only cookies
   with configurable SameSite and Secure attributes based on
   environment, preventing XSS-based token theft.

4. **Event-driven notifications**: All social actions (follow, like,
   comment, rank) trigger real-time notifications through a centralized
   `sendRealtimeNotification()` helper that persists to MongoDB and
   pushes to connected sockets simultaneously.

### Database Schema

The MongoDB database contains six collections:

- **Users**: account credentials, profile data, social graph
  (followers, following, friends), interests array, rank with voters
  array, blocked users, and online status.

- **Posts**: user-generated text content with like/dislike arrays and
  counts, supporting toggle-based reactions.

- **Comments**: nested under posts with their own like system.

- **Chats**: saved conversation history stored as a flexible object
  (supports both indexed-object and array formats for backward
  compatibility).

- **Notifications**: typed notification records with sender population,
  read/unread tracking, and reference linking to related documents.

- **MatchHistories**: records of all matchmaking pairings with match
  type, score, and common interests for the matching algorithm's
  history penalty.

### Real-Time Communication

The platform uses two real-time technologies:

1. **Socket.IO** for text messaging, typing indicators, matchmaking
   coordination, follow/like actions during chat, notification
   delivery, and WebRTC signaling.

2. **WebRTC** for peer-to-peer video and audio calls, using Google's
   public STUN server for NAT traversal. The signaling is handled
   through Socket.IO's room-based messaging.
