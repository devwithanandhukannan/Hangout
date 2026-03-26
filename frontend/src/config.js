/**
 * config.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Derives the backend URL from the page's own hostname at runtime.
 *
 * Why:
 *   When the app is served on a LAN (e.g. http://192.168.1.10:5173), every
 *   client that opens it gets the page from that IP.  If the frontend still
 *   hard-codes "localhost:8000" those OTHER clients get ERR_CONNECTION_REFUSED
 *   because "localhost" resolves to THEIR OWN machine, not the server.
 *
 * Solution:
 *   Read window.location.hostname at runtime → always points to the machine
 *   that actually served the page → backend is on the same machine → works.
 *
 * API calls use the Vite dev-proxy (/api → backend) during development.
 * For production builds (viteSingleFile) the proxy is gone, so we fall back
 * to the direct URL.
 *
 * Usage:
 *   import { SOCKET_URL, API_BASE } from "./config";
 */

const hostname = window.location.hostname;
const protocol = window.location.protocol;
const BACKEND_PORT = 8000;

export const SOCKET_URL = `${protocol}//${hostname}:${BACKEND_PORT}`;
export const API_BASE = "/api";

// Base for REST calls.
// In Vite dev-server the proxy rewrites /api → http://localhost:8000,
// but when a remote client opens the page the proxy runs on the SERVER
// machine — all fetches go through the Vite dev-server which is already
// on the right host — so /api still works.
// For a production build served statically, fall back to direct URL.
