import { Navigate } from "react-router-dom";
import { useAuth } from "./AuthContext";

/**
 * Wraps protected pages.
 * • While session is resolving → spinner (AuthProvider already handles this,
 *   but we guard here too in case loading is somehow still true).
 * • No user (cookie missing / expired) → redirect to /login.
 * • User present → render children.
 */
export default function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="h-screen bg-black text-white flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="h-8 w-8 rounded-full border-2 border-white border-t-transparent animate-spin" />
          <span className="text-gray-400 text-sm">Authenticating…</span>
        </div>
      </div>
    );
  }

  // No valid JWT cookie → backend returned 401 → user is null → redirect
  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return children;
}
