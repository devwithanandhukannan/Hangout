import { useState } from "react";
import { Link, useNavigate, Navigate } from "react-router-dom";
import { signin } from "../api";
import { useAuth } from "../AuthContext";
import { useToastHelpers } from "../Toast";
import { FaLock, FaUser, FaArrowRight } from "react-icons/fa";

export default function LoginPage() {
  const navigate = useNavigate();
  const { setUser, user } = useAuth();
  const toast = useToastHelpers();
  const [form, setForm] = useState({ username: "", password: "" });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  // Already logged in → go to dashboard
  if (user) return <Navigate to="/dashboard" replace />;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const data = await signin({ username: form.username, password: form.password });
      setUser(data.user || data);
      toast.success(`Welcome back, ${(data.user || data).username}!`);
      navigate("/dashboard");
    } catch (err) {
      const msg = err.message || "Login failed";
      setError(msg);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#030303] text-white antialiased flex flex-col relative overflow-hidden">
      {/* Background glow radial */}
      <div className="absolute top-[-10%] right-[-10%] w-[50%] h-[50%] rounded-full bg-blue-500/5 blur-[120px] pointer-events-none pulse-glow-bg" />
      <div className="absolute bottom-[-15%] left-[-10%] w-[50%] h-[50%] rounded-full bg-rose-500/5 blur-[120px] pointer-events-none pulse-glow-bg" style={{ animationDelay: "-4s" }} />

      <header className="w-full border-b border-white/5 bg-black/20 backdrop-blur-md z-10">
        <div className="max-w-5xl mx-auto px-6 py-5 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2">
            <div className="h-6 w-6 rounded-lg bg-white flex items-center justify-center font-black text-black text-xs tracking-wider">H</div>
            <span className="font-bold tracking-tight text-sm text-white/90">Hangout</span>
          </Link>
          <nav className="flex items-center gap-6 text-xs text-white/50">
            <Link to="/signup" className="hover:text-white transition-colors">Join Hangout</Link>
          </nav>
        </div>
      </header>

      <main className="flex-1 flex items-center justify-center px-6 py-10 z-10">
        <div className="w-full max-w-[420px] glass-panel rounded-3xl p-8 space-y-6 animate-float" style={{ animationDuration: "12s" }}>
          <div className="text-center space-y-2">
            <h1 className="text-2xl font-bold tracking-tight bg-gradient-to-b from-white to-white/70 bg-clip-text text-transparent">Welcome back</h1>
            <p className="text-xs text-white/50">
              Sign in to return to your real-time matching space.
            </p>
          </div>

          {error && (
            <div className="text-xs text-rose-400 bg-rose-500/5 border border-rose-500/20 rounded-xl px-4 py-2.5 text-center">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <label htmlFor="login-identifier" className="block text-xs font-semibold tracking-wide text-white/60">
                Username
              </label>
              <div className="relative">
                <FaUser className="absolute left-4 top-1/2 -translate-y-1/2 text-white/30 text-xs" />
                <input
                  id="login-identifier"
                  name="username"
                  type="text"
                  autoComplete="username"
                  required
                  placeholder="Your username"
                  value={form.username}
                  onChange={(e) => setForm({ ...form, username: e.target.value })}
                  className="w-full rounded-xl glass-input pl-10 pr-4 py-3 text-xs outline-none focus:border-white focus:bg-white/[0.06]"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label htmlFor="login-password" className="block text-xs font-semibold tracking-wide text-white/60">
                  Password
                </label>
                <Link to="/forgot-password" className="text-[10px] text-white/40 hover:text-white transition-colors">Forgot Password?</Link>
              </div>
              <div className="relative">
                <FaLock className="absolute left-4 top-1/2 -translate-y-1/2 text-white/30 text-xs" />
                <input
                  id="login-password"
                  name="password"
                  type="password"
                  autoComplete="current-password"
                  required
                  placeholder="Your password"
                  value={form.password}
                  onChange={(e) => setForm({ ...form, password: e.target.value })}
                  className="w-full rounded-xl glass-input pl-10 pr-4 py-3 text-xs outline-none focus:border-white focus:bg-white/[0.06]"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full glass-btn-primary py-3 rounded-full text-xs font-semibold flex items-center justify-center gap-2 disabled:opacity-50 mt-2"
            >
              {loading ? "Signing in…" : "Sign In"}
              <FaArrowRight size={10} />
            </button>
          </form>

          <p className="text-xs text-center text-white/50">
            New here?{" "}
            <Link to="/signup" className="text-white hover:underline font-semibold transition-colors">
              Create an account
            </Link>
          </p>
        </div>
      </main>
    </div>
  );
}
