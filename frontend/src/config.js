/**
 * config.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Derives the backend URL from environment variables or uses a fallback.
 *
 * Why:
 *   In production, the frontend and backend are on different domains.
 *   This config uses VITE_BACKEND_URL to specify the actual backend URL.
 *
 * Usage:
 *   import { SOCKET_URL, API_BASE, BACKEND_URL } from "./config";
 */

const isDev = import.meta.env.DEV;
const backendUrl = import.meta.env.VITE_BACKEND_URL || "https://hangout-all4.onrender.com";

export const BACKEND_URL = backendUrl;
export const SOCKET_URL = backendUrl;
export const API_BASE = isDev ? "/api" : backendUrl;

// Base for REST calls.
// In Vite dev-server the proxy rewrites /api → backend,
// and in production builds, the direct backend URL is used.