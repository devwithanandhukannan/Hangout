import { createContext, useContext, useState, useEffect } from "react";
import { getProfile } from "./api";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // On mount, try to restore session from the JWT cookie
  useEffect(() => {
    getProfile()
      .then((data) => {
        // Profile endpoint returns the user object directly (no wrapper)
        setUser(data);
      })
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  const logout = () => {
    setUser(null);
    // The cookie is httpOnly so we can't clear it from JS,
    // but the server will reject expired tokens. Redirect to login.
  };

  const refreshUser = () =>
    getProfile()
      .then((data) => setUser(data))
      .catch(() => setUser(null));

  if (loading) {
    return (
      <div className="min-h-screen bg-black text-white flex items-center justify-center">
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
  return useContext(AuthContext);
}
