import { useState } from "react";
import { Link, useNavigate, Navigate } from "react-router-dom";
import { signin } from "../api";
import { useAuth } from "../AuthContext";

export default function LoginPage() {
  const navigate = useNavigate();
  const { setUser, user } = useAuth();
  const [form, setForm] = useState({ username: "", password: "" });

  // Already logged in → go to dashboard
  if (user) return <Navigate to="/dashboard" replace />;
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const data = await signin({ username: form.username, password: form.password });
      setUser(data.user || data);
      navigate("/dashboard");
    } catch (err) {
      setError(err.message || "Login failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-black text-white antialiased flex flex-col relative overflow-hidden">
      <div className="pointer-events-none absolute inset-0 -z-10 opacity-60 bg-[radial-gradient(circle_at_top,_rgba(255,255,255,0.12),transparent_60%),radial-gradient(circle_at_bottom,_rgba(255,255,255,0.08),transparent_65%)]"></div>

      <header className="w-full border-b border-white/10">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex items-center justify-between text-sm">
          <div className="font-semibold tracking-tight text-white/80">Hangout</div>
          <nav className="flex items-center gap-4 text-xs sm:text-sm text-white/70">
            <a href="#" className="hover:text-white transition-colors">About</a>
            <a href="#" className="hover:text-white transition-colors">Privacy &amp; Security</a>
          </nav>
        </div>
      </header>

      <main className="flex-1 flex items-center justify-center px-4 sm:px-6 lg:px-8 py-10">
        <div className="w-full max-w-md bg-white/5 border border-white/10 rounded-3xl backdrop-blur-xl shadow-[0_0_45px_rgba(0,0,0,0.85)] px-6 sm:px-8 py-8 space-y-6">
          <div className="text-center space-y-2">
            <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight">Welcome back</h1>
            <p className="text-xs sm:text-sm text-white/60">
              Log in to Hangout and jump back into real‑time conversations.
            </p>
          </div>

          {error && (
            <div className="text-xs text-red-400 bg-red-400/10 border border-red-400/20 rounded-xl px-3 py-2 text-center">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="space-y-1.5">
              <label htmlFor="login-identifier" className="block text-xs font-medium tracking-wide text-white/70">
                Username
              </label>
              <input
                id="login-identifier"
                name="username"
                type="text"
                autoComplete="username"
                required
                value={form.username}
                onChange={(e) => setForm({ ...form, username: e.target.value })}
                className="w-full rounded-xl bg-black/40 border border-white/20 px-3 py-2.5 text-sm outline-none focus:border-white focus:bg-black/60 transition-colors"
              />
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <label htmlFor="login-password" className="font-medium tracking-wide text-white/70">
                  Password
                </label>
                <Link to="/forgot-password" className="text-white/60 hover:text-white">Forgot?</Link>
              </div>
              <input
                id="login-password"
                name="password"
                type="password"
                autoComplete="current-password"
                required
                value={form.password}
                onChange={(e) => setForm({ ...form, password: e.target.value })}
                className="w-full rounded-xl bg-black/40 border border-white/20 px-3 py-2.5 text-sm outline-none focus:border-white focus:bg-black/60 transition-colors"
              />
            </div>

            <div className="flex items-center justify-between text-xs text-white/60">
              <label className="inline-flex items-center gap-2 cursor-pointer">
                <input type="checkbox" className="h-3.5 w-3.5 rounded border border-white/30 bg-black/60 text-white focus:ring-0" />
                <span>Remember this device</span>
              </label>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full mt-1 inline-flex items-center justify-center rounded-full bg-white text-black text-sm font-semibold py-2.5 border border-white hover:bg-black hover:text-white transition-colors disabled:opacity-50"
            >
              {loading ? "Logging in…" : "Log in"}
            </button>
          </form>

          <p className="text-xs text-center text-white/60">
            New here?{" "}
            <Link to="/signup" className="text-white hover:underline font-medium">
              Create a Hangout account
            </Link>
            .
          </p>
        </div>
      </main>
    </div>
  );
}
