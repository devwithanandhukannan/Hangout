# Project Scope and Key Features

## Scope Definition

Hangout is scoped as a full-stack web application that delivers real-time
communication and social networking capabilities. The project encompasses
user management, real-time messaging, video calling, content creation,
social graph management, intelligent matchmaking, and notification systems
— all within a single deployable unit orchestrated through Docker Compose.

The platform targets users aged 16 and above who seek spontaneous,
interest-based conversations with strangers while maintaining the ability
to build lasting connections through the follow and friend systems.

---

## Feature Catalog

### 1. User Authentication and Account Management

**Registration**: users create accounts with a unique username, email
address, and password. Passwords are hashed with bcrypt (10 salt rounds)
before storage. Duplicate username and email checks are performed before
account creation.

**Login**: credential-based authentication issues a JWT token stored in
an HTTP-only cookie with a 7-day expiration. The cookie configuration
adapts between development (lax SameSite) and production (none SameSite
with Secure flag) environments.

**Session Persistence**: the `AuthContext` on the frontend attempts to
validate the existing cookie on mount by calling the profile endpoint,
restoring the session without requiring re-login.

**Logout**: clears the JWT cookie and updates the user's online status
and last-seen timestamp in the database.

---

### 2. Profile Management

**Editable Fields**: username, email, bio (text), password, and avatar
image.

**Avatar Upload**: profile images are uploaded through a multipart form
using Multer with an S3 storage backend. Files are validated for type
(image only) and size (2MB maximum). Old avatars are automatically
deleted from S3 when replaced. Avatar URLs are stored as S3 object
URLs in the user document.

**Profile Display**: the settings page shows follower count, following
count, friends count, post count, and rank score. Clickable lists of
followers, following, and friends link to individual user profiles.

---

### 3. Interest System

**Adding Interests**: users add free-text interest tags (e.g., "gaming",
"music", "movies") through the dashboard or settings page. Tags are
stored as an array of strings in the user document.

**Removing Interests**: clicking a tag removes it and persists the
change immediately.

**Matching Integration**: interests are the primary factor in the
matchmaking algorithm, with each common interest contributing 50 points
to the match score.

---

### 4. Intelligent Matchmaking Algorithm

The matchmaking system uses a multi-factor scoring algorithm to find
the best available partner:

```
Match Score = (Common Interests × 50)
            + Rank Proximity Bonus (max 30)
            + Combined Rank Bonus (max 20)
            - Recent Match Penalty (30 per match in last 24h)
```

**Interest Matching** (weight: 50 per match): the most heavily weighted
factor. Users who share interests like "gaming" and "music" get 100
bonus points.

**Rank Proximity Bonus** (weight: max 30): calculated as
`max(0, 30 - rankDifference × 2)`. Users with similar rank scores are
preferred, encouraging balanced conversations.

**Combined Rank Bonus** (weight: max 20): calculated as
`min(20, combinedRank × 2)`. Higher-ranked users get a slight bonus,
rewarding positive community participation.

**History Penalty** (weight: -30 per recent match): repeated pairings
within 24 hours are penalized to encourage meeting new people.

**Blocked User Filtering**: blocked users receive a score of -1 and
are excluded from matching entirely.

**Fallback**: if no scored match is available, the system falls back
to a random match from the queue, still filtering blocked users.

---

### 5. Real-Time Text Chat

**Private Messaging**: messages are sent through Socket.IO rooms. Each
chat session creates a room named by sorting and joining both user IDs
(e.g., `userId1_userId2`), ensuring consistent room names regardless
of who initiated.

**Typing Indicators**: when a user types, a `typing` event is emitted
to the room. A 2-second debounce timer automatically sends a
stop-typing event if the user pauses.

**Message History**: during a session, messages are accumulated in a
`chatDataRef` object (indexed by message order). Users can save the
complete conversation to MongoDB after the chat ends.

**Message Format**: each message includes sender identity, text content,
and timestamp. The frontend normalizes messages from both the legacy
object format and the modern array format for backward compatibility
with saved chats.

---

### 6. WebRTC Video and Audio Calls

**Initiating Calls**: either user in a chat session can start a video
call. The initiator captures local media (camera + microphone), creates
an RTCPeerConnection with Google's STUN server, and sends an SDP offer
through Socket.IO signaling.

**Answering Calls**: the receiving user automatically captures their
own media, creates a peer connection, sets the remote description,
creates an answer, and sends it back through signaling.

**ICE Candidates**: exchanged through Socket.IO events to establish
the optimal peer-to-peer path through NATs and firewalls.

**Controls**: users can toggle microphone and camera independently
during a call. The local video appears as a picture-in-picture overlay,
while the remote video fills the main panel.

**Ending Calls**: either user can end the video call while keeping the
text chat active. All media tracks are stopped and peer connections
are closed.

---

### 7. Direct Friend Chat

**Requesting**: from the dashboard or feed, users can click a friend
to send a direct chat request. The request is delivered as a Socket.IO
event to the friend's active connection.

**Accepting**: the friend receives a toast notification with Accept
and Decline buttons. Accepting creates a room and starts the chat
session with match type "direct".

**Declining**: sends a decline event back to the requester, who
receives a toast notification.

**Cancelling**: the requester can cancel a pending request before the
friend responds.

---

### 8. Community Feed

**Feed Algorithm**: displays posts from users the current user follows,
plus the user's own posts, sorted by creation date (newest first).
Paginated with 20 posts per page and a "Load more" button.

**Post Interactions**: each post shows like count, dislike count, and
the current user's reaction state. Toggling a reaction removes the
opposite reaction if present.

**Author Context**: each post card shows the author's avatar, username,
rank, and the time since posting. Non-own posts include Follow/Unfollow
and Chat buttons (for friends).

---

### 9. Posts and Comments

**Creating Posts**: text-only posts with a 280-character limit.
Published posts trigger notifications to all followers.

**Deleting Posts**: post owners can delete their posts. Deletion
cascades to remove all associated comments and notifications.

**Comments**: users can comment on posts. Comments support their own
like system. Post owners and comment authors can delete comments.

**Real-Time Updates**: post reactions can be broadcast through
Socket.IO, enabling live reaction counts across all connected clients.

---

### 10. Follow/Friend System

**Following**: a toggle action. Following a user adds them to your
"following" list and adds you to their "followers" list.

**Mutual Follow Detection**: when a follow action creates a mutual
follow (A follows B and B already follows A), both users are
automatically added to each other's "friends" list. Both receive a
"You're now friends! 🎉" notification.

**Unfollowing**: removes the follow relationship and, if they were
friends, removes the friend relationship from both sides.

**Blocked Users**: following a blocked user (or being blocked) throws
a 403 error. Blocking a user automatically unfollows in both
directions and removes any friend relationship.

---

### 11. Ranking (Heart) System

**Liking**: users can "heart" another user's profile, incrementing
their rank count. Each user can only give one heart per target
(tracked via a voters array).

**Unliking**: toggling the heart again removes it, decrementing the
rank count.

**Leaderboard**: the settings page includes a leaderboard tab showing
the top 20 users by rank, with medal indicators for the top 3.

**In-Chat Liking**: during a chat session, users can heart their
partner directly. The rank update is broadcast to both users in
real-time, and the chat background briefly flashes red as visual
feedback.

---

### 12. Notification System

**Notification Types**: follow, unfollow, post like, post dislike,
comment, rank up, rank down, friend added, new post by followed user,
and comment like.

**Delivery**: notifications are persisted to MongoDB and simultaneously
pushed to connected sockets. The frontend maintains an unread count
badge on the notification bell icon.

**Management**: users can mark all notifications as read, clear all
notifications, or view them paginated in the settings page.

**Real-Time Count**: the unread count is fetched on socket connection
and updated in real-time as new notifications arrive or are marked
as read.

---

### 13. User Search and Discovery

**Username Search**: debounced search (300ms) queries usernames with
case-insensitive regex matching. Results show online status, rank,
and follow state.

**Suggested Users**: the backend suggests users who share interests
with the current user, excluding already-followed and blocked users.
Results are sorted by common interest count, then by rank.

**User Profiles**: public profiles show username, avatar, bio, rank,
follower/following/friend counts, post count, online status, and
relationship state (following, follower, friend, has ranked).

---

### 14. Chat History

**Saving**: after a chat session, users can save the conversation.
The saved chat includes both user references and the complete message
log.

**Viewing**: the chat history page displays saved chats in a sidebar
with a timeline view in the main panel. Messages are shown with
avatars, sender labels, and timestamps.

**Searching**: saved chats can be filtered by partner username.

**Deleting**: individual saved chats can be permanently deleted.

---

### 15. Settings and Account Management

**Tabbed Interface**: the settings page organizes features into five
tabs: Profile, Interests, Notifications, Find People, and Leaderboard.

**Profile Tab**: edit username, email, bio, password, and avatar.
View follower/following/friend lists with clickable links.

**Interests Tab**: add and remove interest tags.

**Notifications Tab**: view, mark as read, and clear notifications.

**Find People Tab**: search users by username and follow/unfollow
from results.

**Leaderboard Tab**: view top-ranked users with follow buttons.
