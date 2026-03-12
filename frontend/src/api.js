/**
 * api.js
 * ─────────────────────────────────────────────────────────────────────────────
 * All HTTP REST calls to the Express backend.
 *
 * During Vite dev-server:
 *   Requests go to /api/* which the Vite proxy rewrites to
 *   http://localhost:8000/* on the SERVER machine.
 *   This means LAN clients (192.168.x.x:5173) also work because the proxy
 *   runs on the server, not on the client.
 *
 * During production (static file):
 *   Vite proxy is gone. We fall back to the direct SOCKET_URL
 *   (same hostname, port 8000) so it still works on LAN.
 */

import { SOCKET_URL } from "./config";

// In dev: use /api (proxied by Vite).  In prod: use direct backend URL.
const isDev = import.meta.env.DEV;
const BASE  = isDev ? "/api" : `${SOCKET_URL}`;

async function request(path, options = {}) {
  const url = `${BASE}${path}`;
  const res = await fetch(url, {
    credentials : "include",
    headers     : {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    ...options,
  });

  let data = {};
  try {
    data = await res.json();
  } catch (_) { /* empty body */ }

  if (!res.ok) throw new Error(data.message || `Request failed (${res.status})`);
  return data;
}

// ── AUTH ──────────────────────────────────────────────────────────────────────
export const signup = (body) =>
  request("/signup", { method: "POST", body: JSON.stringify(body) });

export const signin = (body) =>
  request("/signin", { method: "POST", body: JSON.stringify(body) });

export const logout = () =>
  request("/logout", { method: "POST" });

// ── PROFILE ───────────────────────────────────────────────────────────────────
export const getProfile = () => request("/profile");

export const getUserProfile = (userId) => request(`/user/${userId}`);

export const updateProfile = (body) =>
  request("/update_profile", { method: "PATCH", body: JSON.stringify(body) });

// ── SEARCH ────────────────────────────────────────────────────────────────────
export const searchUsers = (q) =>
  request(`/search/users?q=${encodeURIComponent(q)}`);

// ── LEADERBOARD ───────────────────────────────────────────────────────────────
export const getLeaderboard = (limit = 20) =>
  request(`/leaderboard?limit=${limit}`);

// ── INTERESTS ─────────────────────────────────────────────────────────────────
export const getInterests = () => request("/interests");

export const setInterests = (interestArray) =>
  request("/interests", {
    method : "PATCH",
    body   : JSON.stringify({ interest: interestArray }),
  });

// ── POSTS ─────────────────────────────────────────────────────────────────────
export const getPosts = () => request("/posts");

export const getUserPosts = (userId) => request(`/posts/user/${userId}`);

export const createPost = (content) =>
  request("/post", { method: "POST", body: JSON.stringify({ content }) });

export const deletePost = (postId) =>
  request(`/delete-post/${postId}`, { method: "DELETE" });

export const likePost = (postId) =>
  request(`/post/${postId}/like`, { method: "PATCH" });

export const dislikePost = (postId) =>
  request(`/post/${postId}/dislike`, { method: "PATCH" });

// ── FEED ──────────────────────────────────────────────────────────────────────
export const getFeed = (page = 1, limit = 20) =>
  request(`/feed?page=${page}&limit=${limit}`);

// ── COMMENTS ─────────────────────────────────────────────────────────────────
export const getComments  = (postId)    => request(`/comments/${postId}`);
export const addComment   = (postId, content) =>
  request("/comment", { method: "POST", body: JSON.stringify({ postId, content }) });
export const deleteComment = (commentId) =>
  request(`/delete-comment/${commentId}`, { method: "DELETE" });
export const likeComment  = (commentId) =>
  request(`/comment/${commentId}/like`, { method: "PATCH" });

// ── FOLLOW SYSTEM ─────────────────────────────────────────────────────────────
export const followToggle = (target_user_id) =>
  request("/follow", {
    method : "PATCH",
    body   : JSON.stringify({ target_user_id }),
  });

export const unfollowUser = (unfollow_user_id) =>
  request("/unfollow", {
    method : "PATCH",
    body   : JSON.stringify({ unfollow_user_id }),
  });

export const removeFollower = (follower_user_id) =>
  request("/remove_follower", {
    method : "PATCH",
    body   : JSON.stringify({ follower_user_id }),
  });

// ── RANK ──────────────────────────────────────────────────────────────────────
export const rankUser = (userId) =>
  request(`/rank/${userId}`, { method: "PATCH" });

// ── BLOCK ─────────────────────────────────────────────────────────────────────
export const blockUser = (userId) =>
  request(`/block/${userId}`, { method: "PATCH" });

// ── NOTIFICATIONS ─────────────────────────────────────────────────────────────
export const getNotifications    = (page = 1, limit = 30) =>
  request(`/notifications?page=${page}&limit=${limit}`);

export const markNotificationsRead = (notificationIds = []) =>
  request("/notifications/read", {
    method : "PATCH",
    body   : JSON.stringify({ notificationIds }),
  });

export const clearNotifications  = () =>
  request("/notifications/clear", { method: "DELETE" });

export const getUnreadCount      = () =>
  request("/notifications/unread-count");

// ── CHATS ─────────────────────────────────────────────────────────────────────
export const getChats = () => request("/chats");

export const saveChat = (partnerId, chatData) =>
  request("/save-chat", {
    method : "POST",
    body   : JSON.stringify({ partnerId, chatData }),
  });

export const deleteChat = (chatId) =>
  request(`/chat/${chatId}`, { method: "DELETE" });

// ── MATCH HISTORY ─────────────────────────────────────────────────────────────
export const getMatchHistory = () => request("/match-history");

// ── SUGGESTED USERS ───────────────────────────────────────────────────────────
export const getSuggestedUsers = () => request("/suggested-users");
