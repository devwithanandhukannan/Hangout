const BASE = "http://localhost:8000";

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.message || "Request failed");
  return data;
}

// ── AUTH ──────────────────────────────────────────────────────────────────
export const signup = (body) =>
  request("/signup", { method: "POST", body: JSON.stringify(body) });

export const signin = (body) =>
  request("/signin", { method: "POST", body: JSON.stringify(body) });

// ── PROFILE ───────────────────────────────────────────────────────────────
// Returns: { _id, username, email, interests, followers, following, friends, rank }
export const getProfile = () => request("/profile");

// body: { username?, email?, password? }
export const updateProfile = (body) =>
  request("/update_profile", { method: "PATCH", body: JSON.stringify(body) });

// ── INTERESTS ─────────────────────────────────────────────────────────────
// GET returns: { interests: ["music, song, hacking"] }  (array with one comma-joined string)
export const getInterests = () => request("/interests");

// PATCH body: { interest: "music, song, hacking" }  — replaces all interests
export const setInterests = (interestString) =>
  request("/interests", {
    method: "PATCH",
    body: JSON.stringify({ interest: interestString }),
  });

// ── POSTS ─────────────────────────────────────────────────────────────────
// GET returns: array of posts belonging to current user
export const getPosts = () => request("/posts");

export const createPost = (content) =>
  request("/post", { method: "POST", body: JSON.stringify({ content }) });

export const deletePost = (postId) =>
  request(`/delete-post/${postId}`, { method: "DELETE" });

// ── FEED ──────────────────────────────────────────────────────────────────
// GET returns: array of posts from followed users (+ self), or { message } if none
export const getFeed = () => request("/feed");

// ── COMMENTS ─────────────────────────────────────────────────────────────
export const getComments = (postId) => request(`/comments/${postId}`);

export const addComment = (postId, content) =>
  request("/comment", {
    method: "POST",
    body: JSON.stringify({ postId, content }),
  });

export const deleteComment = (commentId) =>
  request(`/delete-comment/${commentId}`, { method: "DELETE" });

// ── CHATS ─────────────────────────────────────────────────────────────────
// GET returns: { success: true, chats: [...] }
export const getChats = () => request("/chats");

// POST body: { partnerId, chatData: [{ senderId, text }] }
export const saveChat = (partnerId, chatData) =>
  request("/save-chat", {
    method: "POST",
    body: JSON.stringify({ partnerId, chatData }),
  });

export const deleteChat = (chatId) =>
  request(`/chat/${chatId}`, { method: "DELETE" });

// ── FOLLOW / UNFOLLOW ─────────────────────────────────────────────────────
// PATCH /unfollow — toggles follow/unfollow for target user
// body: { unfollow_user_id: "userId" }
export const unfollowUser = (unfollow_user_id) =>
  request("/unfollow", {
    method: "PATCH",
    body: JSON.stringify({ unfollow_user_id }),
  });

// PATCH /remove_follower — removes a follower from your followers list
// body: { follower_user_id: "userId" }  (note: server uses follower_user_id)
export const removeFollower = (follower_user_id) =>
  request("/remove_follower", {
    method: "PATCH",
    body: JSON.stringify({ follower_user_id }),
  });
