import { createContext, useContext, useState, useEffect, useCallback } from "react";
import { API_BASE } from "./config";

const AuthContext = createContext(null);

// API_BASE is "/api" in dev (uses Vite proxy) and full backend URL in production
const PROF_URL  = `${API_BASE}/profile`;
const LOUT_URL  = `${API_BASE}/logout`;

async function fetchProfile() {
  const res = await fetch(PROF_URL, { credentials: "include" });
  if (!res.ok) throw new Error("Not authenticated");
  return res.json();
}

export function AuthProvider({ children }) {
  const [user,    setUser]    = useState(null);
  const [loading, setLoading] = useState(true);

  // ── Restore session from httpOnly cookie on mount ────────────────────────
  useEffect(() => {
    fetchProfile()
      .then((data) => setUser(data))
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  // ── Logout: clear cookie server-side, wipe local state ──────────────────
  const logout = useCallback(async () => {
    try {
      await fetch(LOUT_URL, { method: "POST", credentials: "include" });
    } catch { /* ignore network error */ }
    setUser(null);
  }, []);

  // ── Refresh profile (call after updating username / bio etc.) ───────────
  const refreshUser = useCallback(async () => {
    try {
      const data = await fetchProfile();
      setUser(data);
      return data;
    } catch {
      setUser(null);
      return null;
    }
  }, []);

  // ── Full-screen spinner while session resolves ───────────────────────────
  if (loading) {
    return (
      <div className="h-screen w-screen bg-black text-white flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="h-8 w-8 rounded-full border-2 border-white border-t-transparent animate-spin" />
          <span className="text-gray-400 text-sm">Loading…</span>
        </div>
      </div>
    );
  }

  return (
    <AuthContext.Provider value={{ user, setUser, logout, loading, refreshUser }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be inside <AuthProvider>");
  return ctx;
}
