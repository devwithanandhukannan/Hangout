# Future Enhancements

This document outlines planned improvements and new features that would
enhance the Hangout platform's functionality, scalability, reliability,
and user experience.

---

## 1. TURN Server for Reliable Video Calls

**Current Limitation**: the platform uses only Google's public STUN
server for WebRTC NAT traversal. STUN works for most home networks
but fails when users are behind symmetric NATs or restrictive
corporate firewalls. Approximately 10-15% of peer-to-peer connections
fail without a TURN server.

**Enhancement**: deploy a TURN (Traversal Using Relays around NAT)
server using Coturn, which relays media streams when direct
peer-to-peer connection is impossible.

**Implementation Plan**:
- Deploy Coturn as a Docker container alongside existing services
- Configure ICE servers to include both STUN and TURN endpoints
- Add TURN credentials management (time-limited credentials)
- Estimated video call success rate improvement: 85% to 99%

**Priority**: High

---

## 2. End-to-End Encryption for Messages

**Current State**: messages are transmitted through Socket.IO in
plaintext. While the WebSocket connection uses TLS in production,
the server can read message content.

**Enhancement**: implement end-to-end encryption using the Web
Crypto API (SubtleCrypto) with ECDH key exchange.

**Implementation Plan**:
- Generate ephemeral key pairs per chat session on the client
- Exchange public keys through Socket.IO during chat setup
- Derive shared secret using ECDH
- Encrypt messages with AES-GCM before sending
- Server stores and relays encrypted blobs
- Saved chat history stored encrypted with user's key

**Priority**: Medium

---

## 3. Horizontal Scaling with Redis Adapter

**Current Limitation**: the in-memory stores (activeUsers Map,
waitingQueue array, busyUsers Set) limit deployment to a single
server instance. Socket.IO rooms are also local to one process.

**Enhancement**: replace in-memory state with Redis and use the
Socket.IO Redis adapter for multi-server pub/sub.

**Implementation Plan**:
- Add Redis container to Docker Compose
- Replace `activeUsers` Map with Redis hash
- Replace `waitingQueue` array with Redis sorted set
- Replace `busyUsers` Set with Redis set
- Install `@socket.io/redis-adapter` for cross-server events
- Add sticky sessions or use Redis for session store
- Deploy behind a load balancer (Nginx or HAProxy)

**Architecture**:
```
                    Load Balancer
                   /      |      \
                  /       |       \
            Server 1  Server 2  Server 3
                  \       |       /
                   \      |      /
                    Redis Cluster
                         |
                       MongoDB
```

**Priority**: Medium (needed when concurrent users exceed 500)

---

## 4. Media Messaging (Images, Files, Voice Messages)

**Current State**: chat supports text-only messages. The upload modal
exists in the UI but is non-functional.

**Enhancement**: support image sharing, file transfers, and voice
messages within chat sessions.

**Implementation Plan**:
- Images: upload to S3, send URL through Socket.IO, render inline
- Files: upload to S3 with presigned URLs, share download links
- Voice messages: record using MediaRecorder API, upload audio blob
- Add message types: "text", "image", "file", "voice"
- Add content moderation for uploaded images
- Set file size limits (10MB images, 25MB files, 2min voice)

**Priority**: Medium

---

## 5. Group Chat Rooms

**Current State**: all chat sessions are strictly 1-to-1.

**Enhancement**: allow users to create topic-based group chat rooms
that multiple users can join simultaneously.

**Implementation Plan**:
- New GroupRoom model: { name, topic, members[], maxMembers, createdBy }
- Room discovery page with search and filters
- Real-time member join/leave notifications
- Room moderation (kick, mute, ban by room creator)
- Support up to 50 members per room
- Group video calls using SFU (Selective Forwarding Unit) instead of
  mesh topology

**Priority**: Low

---

## 6. Content Moderation and Safety

**Current State**: no automated content moderation exists. Users can
only block individual accounts.

**Enhancement**: implement multi-layered content moderation for both
text and video content.

**Implementation Plan**:
- Text filtering: integrate a profanity filter library with
  configurable severity levels
- AI moderation: integrate OpenAI Moderation API or Perspective API
  for toxicity detection
- Image moderation: use AWS Rekognition for NSFW image detection
  on uploaded content
- Video moderation: periodic frame capture during video calls with
  automated analysis
- Report system: users can report messages, posts, or users with
  categorized reasons
- Admin dashboard: review queue for reported content with
  ban/warn/dismiss actions
- Rate limiting: prevent spam with per-user message rate limits

**Priority**: High (essential for production deployment)

---

## 7. Push Notifications

**Current State**: notifications are only delivered while the user
has the application open in a browser tab.

**Enhancement**: send push notifications through the browser Push
API and service workers, so users receive alerts even when the tab
is closed.

**Implementation Plan**:
- Register service worker for push events
- Implement VAPID key generation and management
- Store push subscriptions in user documents
- Send push notifications for high-priority events: direct chat
  requests, new messages from friends, new followers
- Allow users to configure notification preferences
- Add email notifications as a fallback for offline users

**Priority**: Medium

---

## 8. Mobile Application

**Current State**: the platform is web-only with responsive design.

**Enhancement**: build native mobile applications for iOS and Android
using React Native, sharing business logic with the web app.

**Implementation Plan**:
- React Native app with shared API client and Socket context
- Native WebRTC integration using react-native-webrtc
- Push notifications via APNs (iOS) and FCM (Android)
- Background socket connection for message delivery
- Camera and microphone permission handling
- App Store and Google Play deployment

**Priority**: Low (long-term roadmap)

---

## 9. Advanced Matching Preferences

**Current State**: matching considers interests, rank, and history
but users cannot set explicit preferences.

**Enhancement**: allow users to configure matching preferences for
more targeted connections.

**Planned Preferences**:
- Age range preference (requires adding age/birthdate to profile)
- Language preference (requires adding language to profile)
- Gender preference (requires adding gender to profile)
- "Interests only" mode: only match with users sharing at least
  one common interest
- Rank range filter: only match within a specified rank range
- Region preference: prefer users from same country/timezone
- "New users" mode: prioritize matching with users who joined
  recently

**Priority**: Low

---

## 10. Analytics Dashboard

**Current State**: no analytics or metrics are collected.

**Enhancement**: provide users and administrators with insights
into platform usage and personal statistics.

**User Analytics**:
- Total conversations held (by week/month)
- Average conversation duration
- Most common interests matched on
- Rank growth over time chart
- Follow/friend growth over time
- Post engagement metrics

**Admin Analytics**:
- Daily/weekly/monthly active users
- Concurrent user counts over time
- Average queue wait time
- Match type distribution (interest vs rank vs random)
- Most popular interests
- User retention rates

**Implementation Plan**:
- Event logging to a time-series collection
- Aggregation pipelines for metric computation
- Chart rendering with Chart.js or Recharts
- Scheduled jobs for daily metric snapshots

**Priority**: Low

---

## 11. Accessibility Improvements

**Current State**: the UI uses semantic HTML but lacks comprehensive
accessibility support.

**Enhancement**: achieve WCAG 2.1 AA compliance across all pages.

**Implementation Plan**:
- Add ARIA labels to all interactive elements
- Ensure keyboard navigation works on all pages
- Add screen reader announcements for real-time events
- Ensure color contrast ratios meet AA standards
- Add focus indicators for all focusable elements
- Provide text alternatives for all non-text content
- Test with screen readers (NVDA, VoiceOver)
- Add skip navigation links
- Ensure all modals trap focus correctly

**Priority**: Medium

---

## 12. Internationalization (i18n)

**Current State**: all UI text is hardcoded in English.

**Enhancement**: support multiple languages with runtime language
switching.

**Implementation Plan**:
- Extract all UI strings to translation files (JSON)
- Integrate react-i18next for translation management
- Support RTL layouts for Arabic, Hebrew, etc.
- Initial languages: English, Spanish, French, German, Japanese
- Allow community-contributed translations
- Date and time formatting per locale

**Priority**: Low

---

## Enhancement Priority Summary

| Priority | Enhancement                        | Effort    |
| -------- | ---------------------------------- | --------- |
| High     | TURN Server for Video Calls        | 1 week    |
| High     | Content Moderation and Safety      | 3 weeks   |
| Medium   | End-to-End Encryption              | 2 weeks   |
| Medium   | Redis Adapter for Scaling          | 2 weeks   |
| Medium   | Media Messaging                    | 2 weeks   |
| Medium   | Push Notifications                 | 1 week    |
| Medium   | Accessibility Improvements         | 2 weeks   |
| Low      | Group Chat Rooms                   | 3 weeks   |
| Low      | Advanced Matching Preferences      | 1 week    |
| Low      | Analytics Dashboard                | 2 weeks   |
| Low      | Mobile Application                 | 8 weeks   |
| Low      | Internationalization               | 2 weeks   |
