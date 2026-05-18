/**
 * config.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Derives the backend URL dynamically without relying on a hardcoded port.
 *
 * Why:
 *   Hardcoding ports can lead to issues in production or different environments.
 *   This update ensures flexibility and compatibility across setups.
 *
 * Usage:
 *   import { SOCKET_URL, API_BASE } from "./config";
 */

const hostname = window.location.hostname;
const protocol = window.location.protocol; // http: or https:

export const SOCKET_URL = `${protocol}//${hostname}`;
export const API_BASE = "/api";

// Base for REST calls.
// In Vite dev-server the proxy rewrites /api → backend,
// and in production builds, the direct URL is used.