# Workflow Diagrams

## Use Case 1: Random Matchmaking Flow

```
┌──────────┐                    ┌──────────┐                    ┌──────────┐
│  User A  │                    │  Server  │                    │  User B  │
└────┬─────┘                    └────┬─────┘                    └────┬─────┘
     │                               │                               │
     │  1. Click "Go" button         │                               │
     │──────────────────────────────▶│                               │
     │       emit('findChat')        │                               │
     │                               │                               │
     │                               │  2. Load User A interests,    │
     │                               │     rank, blocked list        │
     │                               │     from MongoDB              │
     │                               │                               │
     │                               │  3. Check waiting queue       │
     │                               │     Queue is empty            │
     │                               │                               │
     │                               │  4. Add User A to queue       │
     │  5. emit('waitingForPartner') │                               │
     │◀──────────────────────────────│                               │
     │                               │                               │
     │  [User A sees spinner         │                               │
     │   "Finding your match..."]    │                               │
     │                               │                               │
     │                               │         6. Click "Go" button  │
     │                               │◀──────────────────────────────│
     │                               │       emit('findChat')        │
     │                               │                               │
     │                               │  7. Load User B interests,    │
     │                               │     rank, blocked list        │
     │                               │                               │
     │                               │  8. Score all queue users     │
     │                               │     against User B:           │
     │                               │                               │
     │                               │     User A score:             │
     │                               │     ┌────────────────────┐    │
     │                               │     │ Common interests×50│    │
     │                               │     │ + Rank proximity   │    │
     │                               │     │ + Combined rank    │    │
     │                               │     │ - History penalty  │    │
     │                               │     │ = Total score      │    │
     │                               │     └────────────────────┘    │
     │                               │                               │
     │                               │  9. Best match found: User A  │
     │                               │     Remove A from queue       │
     │                               │                               │
     │                               │  10. Create room:             │
     │                               │      "userA_userB" (sorted)   │
     │                               │      Both join Socket room    │
     │                               │      Both marked as busy      │
     │                               │                               │
     │                               │  11. Save MatchHistory        │
     │                               │      to MongoDB               │
     │                               │                               │
     │  12. emit('chatStarted')      │      emit('chatStarted')  12.│
     │◀──────────────────────────────│──────────────────────────────▶│
     │   { room, partnerId: B,       │   { room, partnerId: A,      │
     │     matchType: 'interest',    │     matchType: 'interest',   │
     │     commonInterests: [...],   │     commonInterests: [...],  │
     │     matchScore: 150 }         │     matchScore: 150 }        │
     │                               │                               │
     │  [Both users see              │  [Both users see              │
     │   "Connected" status          │   "Connected" status          │
     │   and can start chatting]     │   and can start chatting]     │
     │                               │                               │
     ▼                               ▼                               ▼
```

---

## Use Case 2: Direct Friend Chat Flow

```
┌──────────┐                    ┌──────────┐                    ┌──────────┐
│  User A  │                    │  Server  │                    │  User B  │
│(Requester)│                   │          │                    │(Receiver)│
└────┬─────┘                    └────┬─────┘                    └────┬─────┘
     │                               │                               │
     │  1. Click friend name         │                               │
     │     on Dashboard              │                               │
     │                               │                               │
     │  2. Navigate to /chat         │                               │
     │     with state:               │                               │
     │     { friendId, friendName,   │                               │
     │       directRoom }            │                               │
     │                               │                               │
     │  3. emit('directChatRequest') │                               │
     │──────────────────────────────▶│                               │
     │   { toId: B, room: uuid }     │                               │
     │                               │  4. Look up User B socket    │
     │                               │     in activeUsers Map       │
     │                               │                               │
     │                               │     emit('directChatRequest') │
     │                               │──────────────────────────────▶│
     │                               │   { fromId: A,               │
     │                               │     fromName: "UserA",       │
     │                               │     room: uuid }             │
     │                               │                               │
     │  [User A sees:                │  [User B sees toast:          │
     │   "Waiting for UserB          │   "UserA wants to chat!"     │
     │    to accept..."]             │   [Accept] [Decline]]        │
     │                               │                               │
     │                               │                               │
     │            ┌─────────────── OPTION A: ACCEPT ──────────────┐  │
     │            │                                               │  │
     │            │           5a. Click "Accept"                   │  │
     │            │               emit('directChatAccept')        │  │
     │            │◀──────────────────────────────────────────────│  │
     │            │   { toId: A, room: uuid }                     │  │
     │            │                                               │  │
     │            │  6a. Both sockets join room                   │  │
     │            │      Both marked as busy                      │  │
     │            │                                               │  │
     │  7a. emit('chatStarted')     emit('chatStarted')       7a.│  │
     │◀───────────│───────────────────────────────────────────────│──│
     │   { room, partnerId: B,    { room, partnerId: A,          │  │
     │     matchType: 'direct' }    matchType: 'direct' }        │  │
     │            │                                               │  │
     │            └───────────────────────────────────────────────┘  │
     │                               │                               │
     │            ┌─────────────── OPTION B: DECLINE ─────────────┐  │
     │            │                                               │  │
     │            │           5b. Click "Decline"                  │  │
     │            │               emit('directChatDecline')       │  │
     │            │◀──────────────────────────────────────────────│  │
     │            │   { toId: A, room: uuid }                     │  │
     │            │                                               │  │
     │  6b. emit('directChatDeclined')                            │  │
     │◀───────────│                                               │  │
     │   { byName: "UserB" }                                      │  │
     │            │                                               │  │
     │  [Toast: "UserB declined      [Toast dismissed]            │  │
     │   your request"]              │                            │  │
     │            │                                               │  │
     │            └───────────────────────────────────────────────┘  │
     │                               │                               │
     ▼                               ▼                               ▼
```

---

## Use Case 3: Text Messaging During Chat

```
┌──────────┐                    ┌──────────┐                    ┌──────────┐
│  User A  │                    │  Server  │                    │  User B  │
└────┬─────┘                    └────┬─────┘                    └────┬─────┘
     │                               │                               │
     │  1. Start typing              │                               │
     │     emit('typing',            │                               │
     │      { isTyping: true })      │                               │
     │──────────────────────────────▶│                               │
     │                               │  emit('partnerTyping')        │
     │                               │──────────────────────────────▶│
     │                               │                               │
     │                               │  [User B sees typing dots     │
     │                               │   animation: ● ● ●]          │
     │                               │                               │
     │  2. Press Enter               │                               │
     │     - Add to local messages   │                               │
     │     - Add to chatDataRef      │                               │
     │     - emit('privateMessage',  │                               │
     │       { text, room })         │                               │
     │     - emit('typing',          │                               │
     │       { isTyping: false })    │                               │
     │──────────────────────────────▶│                               │
     │                               │                               │
     │                               │  3. socket.to(room).emit     │
     │                               │     ('privateMessage')       │
     │                               │     [Sends to room EXCEPT    │
     │                               │      the sender]             │
     │                               │──────────────────────────────▶│
     │                               │   { senderId: A,             │
     │                               │     text: "Hello!",          │
     │                               │     timestamp: Date }        │
     │                               │                               │
     │                               │  4. User B's onPrivateMsg:   │
     │                               │     - Check senderId ≠ myId  │
     │                               │     - Add to messages state  │
     │                               │     - Add to chatDataRef     │
     │                               │     - Clear typing indicator │
     │                               │                               │
     │                               │  [Message appears in User B's│
     │                               │   chat panel]                │
     │                               │                               │
     │  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  │
     │                               │                               │
     │  5. Click "Save chat"         │                               │
     │     POST /api/save-chat       │                               │
     │     { partnerId: B,           │                               │
     │       chatData: {             │                               │
     │         0: { user: "me",      │                               │
     │              message: "Hi",   │                               │
     │              time: "14:30" }, │                               │
     │         1: { user: "partner", │                               │
     │              message: "Hey",  │                               │
     │              time: "14:31" }  │                               │
     │       }                       │                               │
     │     }                         │                               │
     │──────────────────────────────▶│                               │
     │                               │                               │
     │                               │  6. Create Chat document      │
     │                               │     { users: [A, B],         │
     │                               │       messages: chatData }   │
     │                               │                               │
     │  7. { success: true }         │                               │
     │◀──────────────────────────────│                               │
     │                               │                               │
     ▼                               ▼                               ▼
```

---

## Use Case 4: WebRTC Video Call Flow

```
┌──────────┐                    ┌──────────┐                    ┌──────────┐
│  User A  │                    │  Server  │                    │  User B  │
│ (Caller) │                    │(Signaling)│                   │(Receiver)│
└────┬─────┘                    └────┬─────┘                    └────┬─────┘
     │                               │                               │
     │  1. Click "Start Video Call"  │                               │
     │     getUserMedia()            │                               │
     │     → local stream            │                               │
     │     → show in PIP preview     │                               │
     │                               │                               │
     │  2. Create RTCPeerConnection  │                               │
     │     Add local tracks          │                               │
     │     Set ontrack handler       │                               │
     │     Set onicecandidate        │                               │
     │                               │                               │
     │  3. createOffer()             │                               │
     │     setLocalDescription()     │                               │
     │                               │                               │
     │  4. emit('signal',           │                               │
     │      { data: { sdp: offer }})│                               │
     │──────────────────────────────▶│                               │
     │                               │  5. socket.to(room).emit     │
     │                               │     ('signal')               │
     │                               │──────────────────────────────▶│
     │                               │                               │
     │                               │  6. Receive SDP offer         │
     │                               │     getUserMedia()            │
     │                               │     → local stream            │
     │                               │     Create RTCPeerConnection  │
     │                               │     Add local tracks          │
     │                               │     setRemoteDescription()    │
     │                               │                               │
     │                               │  7. createAnswer()            │
     │                               │     setLocalDescription()     │
     │                               │                               │
     │                               │     emit('signal',            │
     │                               │      { data: { sdp: answer }})│
     │                               │◀──────────────────────────────│
     │  8. socket.to(room)           │                               │
     │     .emit('signal')           │                               │
     │◀──────────────────────────────│                               │
     │                               │                               │
     │  9. setRemoteDescription()    │                               │
     │                               │                               │
     │  ═══════ ICE Candidate Exchange (both directions) ══════════  │
     │                               │                               │
     │  10. onicecandidate fires     │                               │
     │      emit('signal',          │                               │
     │       { data: { candidate }})│                               │
     │──────────────────────────────▶│──────────────────────────────▶│
     │                               │  11. addIceCandidate()        │
     │                               │                               │
     │                               │  12. onicecandidate fires     │
     │      emit('signal',          │◀──────────────────────────────│
     │◀──────────────────────────────│   { data: { candidate }}      │
     │  13. addIceCandidate()        │                               │
     │                               │                               │
     │  ═══════ Peer-to-Peer Connection Established ═══════════════  │
     │                               │                               │
     │  14. ontrack fires            │           ontrack fires    14.│
     │      Remote video appears     │      Remote video appears     │
     │      in main panel            │      in main panel            │
     │                               │                               │
     │◀═══════════════════════ P2P Video/Audio Stream ════════════▶│
     │         (Direct peer-to-peer, not through server)             │
     │                               │                               │
     ▼                               ▼                               ▼
```

---

## Use Case 5: Follow and Friend Detection Flow

```
┌──────────┐                    ┌──────────┐                    ┌──────────┐
│  User A  │                    │  Server  │                    │  User B  │
└────┬─────┘                    └────┬─────┘                    └────┬─────┘
     │                               │                               │
     │  1. Click "Follow" on         │                               │
     │     User B's profile          │                               │
     │     PATCH /follow             │                               │
     │     { target_user_id: B }     │                               │
     │──────────────────────────────▶│                               │
     │                               │                               │
     │                               │  2. Load both users           │
     │                               │     Check blocked lists       │
     │                               │     Check existing follow     │
     │                               │                               │
     │                               │  3. A.following.add(B)        │
     │                               │     B.followers.add(A)        │
     │                               │                               │
     │                               │  4. Check mutual follow:      │
     │                               │     Is A in B.following?      │
     │                               │                               │
     │            ┌──── YES: B already follows A ────┐               │
     │            │                                  │               │
     │            │  5a. A.friends.add(B)             │               │
     │            │      B.friends.add(A)             │               │
     │            │                                  │               │
     │            │  6a. Notify A: "friends! 🎉"      │               │
     │            │      Notify B: "friends! 🎉"      │               │
     │            │                                  │               │
     │            └──────────────────────────────────┘               │
     │                               │                               │
     │            ┌──── NO: One-way follow ──────────┐               │
     │            │                                  │               │
     │            │  5b. No friend relationship       │               │
     │            │      Just follower/following      │               │
     │            │                                  │               │
     │            └──────────────────────────────────┘               │
     │                               │                               │
     │                               │  7. Save both users           │
     │                               │                               │
     │                               │  8. Create notification:      │
     │                               │     "A started following you" │
     │                               │     Save to MongoDB           │
     │                               │                               │
     │                               │     emit('notification')      │
     │                               │──────────────────────────────▶│
     │                               │                               │
     │                               │  9. emit('followUpdate')      │
     │  emit('followUpdate')         │     to both users             │
     │◀──────────────────────────────│──────────────────────────────▶│
     │  { action: 'followed',       │  { action: 'followed',        │
     │    isFriend: true/false }     │    followersCount: N,         │
     │                               │    isFriend: true/false }     │
     │                               │                               │
     │  10. Response:                │                               │
     │  { message: "Followed",      │                               │
     │    isFriend: true/false }     │                               │
     │◀──────────────────────────────│                               │
     │                               │                               │
     ▼                               ▼                               ▼
```

---

## System-Level Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Docker Compose                                │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                    hangout-frontend (Nginx)                     │    │
│  │                        Port 3000:80                             │    │
│  │                                                                 │    │
│  │   ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐     │    │
│  │   │  React App   │  │  Static      │  │  Nginx Reverse   │     │    │
│  │   │  (SPA)       │  │  Assets      │  │  Proxy Config    │     │    │
│  │   │              │  │  (JS/CSS)    │  │                  │     │    │
│  │   │ ┌──────────┐ │  │              │  │  /api/*  ──────┐ │     │    │
│  │   │ │AuthCtx   │ │  │              │  │  /socket.io/* ─┤ │     │    │
│  │   │ │SocketCtx │ │  │              │  │                │ │     │    │
│  │   │ │Toast     │ │  │              │  │  /* ──▶ React  │ │     │    │
│  │   │ │Pages     │ │  │              │  │        SPA     │ │     │    │
│  │   │ └──────────┘ │  │              │  └────────┬───────┘ │     │    │
│  │   └──────────────┘  └──────────────┘           │         │     │    │
│  └────────────────────────────────────────────────┤─────────┘     │    │
│                                                    │               │    │
│                                    HTTP + WebSocket│               │    │
│                                                    ▼               │    │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                hangout-backend (Node.js)                        │    │
│  │                     Port 8000                                   │    │
│  │                                                                 │    │
│  │   ┌──────────────────────────────────────────────────────┐      │    │
│  │   │              Express.js Application                  │      │    │
│  │   │                                                      │      │    │
│  │   │  ┌────────┐ ┌──────────┐ ┌────────┐ ┌───────────┐   │      │    │
│  │   │  │  Auth  │ │  Posts   │ │  Feed  │ │  Search   │   │      │    │
│  │   │  │ Routes │ │  Routes  │ │ Route  │ │  Routes   │   │      │    │
│  │   │  └────────┘ └──────────┘ └────────┘ └───────────┘   │      │    │
│  │   │  ┌────────┐ ┌──────────┐ ┌────────┐ ┌───────────┐   │      │    │
│  │   │  │ Follow │ │ Comments │ │  Chat  │ │   Notif   │   │      │    │
│  │   │  │ Routes │ │  Routes  │ │ Routes │ │  Routes   │   │      │    │
│  │   │  └────────┘ └──────────┘ └────────┘ └───────────┘   │      │    │
│  │   └──────────────────────────────────────────────────────┘      │    │
│  │                                                                 │    │
│  │   ┌──────────────────────────────────────────────────────┐      │    │
│  │   │              Socket.IO Server                        │      │    │
│  │   │                                                      │      │    │
│  │   │  ┌────────────┐ ┌──────────┐ ┌───────────────────┐   │      │    │
│  │   │  │ Matchmaking│ │ Private  │ │  WebRTC Signaling │   │      │    │
│  │   │  │   Engine   │ │ Messaging│ │  (SDP + ICE)      │   │      │    │
│  │   │  └────────────┘ └──────────┘ └───────────────────┘   │      │    │
│  │   │  ┌────────────┐ ┌──────────┐ ┌───────────────────┐   │      │    │
│  │   ��  │  Direct    │ │ In-Chat  │ │  Online Status    │   │      │    │
│  │   │  │  Chat Req  │ │ Actions  │ │  Tracking         │   │      │    │
│  │   │  └────────────┘ └──────────┘ └───────────────────┘   │      │    │
│  │   └──────────────────────────────────────────────────────┘      │    │
│  │                                                                 │    │
│  │   ┌──────────────────────────┐  ┌────────────────────────┐      │    │
│  │   │   In-Memory State       │  │   External Services    │      │    │
│  │   │                         │  │                        │      │    │
│  │   │   activeUsers: Map      │  │   AWS S3               │      │    │
│  │   │   waitingQueue: Array   │  │   (Avatar Storage)     │      │    │
│  │   │   busyUsers: Set        │  │                        │      │    │
│  │   └──────────────────────────┘  └────────────────────────┘      │    │
│  └──────────────────────────┬──────────────────────────────────────┘    │
│                              │ Mongoose ODM                             │
│                              ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                    hangout-mongo (MongoDB 7)                    │    │
│  │                        Port 27017                               │    │
│  │                                                                 │    │
│  │   ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐  │    │
│  │   │  users   │ │  posts   │ │ comments │ │  notifications   │  │    │
│  │   └──────────┘ └──────────┘ └──────────┘ └──────────────────┘  │    │
│  │   ┌──────────┐ ┌──────────────────┐                            │    │
│  │   │  chats   │ │  matchhistories  │     Volume: mongo-data     │    │
│  │   └──────────┘ └──────────────────┘                            │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│                         Network: hangout-net (bridge)                    │
└─────────────────────────────────────────────────────────────────────────┘
```
