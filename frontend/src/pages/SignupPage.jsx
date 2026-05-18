import { useState } from "react";
import { Link, useNavigate, Navigate } from "react-router-dom";
import { signup } from "../api";
import { useAuth } from "../AuthContext";
import { useToastHelpers } from "../Toast";
import { FaUser, FaEnvelope, FaLock, FaArrowRight } from "react-icons/fa";

export default function SignupPage() {
  const navigate = useNavigate();
  const { setUser, user } = useAuth();
  const toast = useToastHelpers();

  if (user) return <Navigate to="/dashboard" replace />;
  const [form, setForm] = useState({ username: "", email: "", password: "", confirm: "" });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    if (form.password !== form.confirm) {
      setError("Passwords do not match");
      toast.error("Passwords do not match");
      return;
    }
    setLoading(true);
    try {
      const data = await signup({ username: form.username, email: form.email, password: form.password });
      setUser(data.user || data);
      toast.success("Account created successfully!");
      navigate("/dashboard");
    } catch (err) {
      setError(err.message || "Signup failed");
      toast.error(err.message || "Signup failed");
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
            <Link to="/login" className="hover:text-white transition-colors">Sign In</Link>
          </nav>
        </div>
      </header>

      <main className="flex-1 flex items-center justify-center px-6 py-10 z-10">
        <div className="w-full max-w-[420px] glass-panel rounded-3xl p-8 space-y-6 animate-float" style={{ animationDuration: "14s" }}>
          <div className="text-center space-y-2">
            <h1 className="text-2xl font-bold tracking-tight bg-gradient-to-b from-white to-white/70 bg-clip-text text-transparent">Create your account</h1>
            <p className="text-xs text-white/50">
              Join Hangout and start connecting with people in seconds.
            </p>
          </div>

          {error && (
            <div className="text-xs text-rose-400 bg-rose-500/5 border border-rose-500/20 rounded-xl px-4 py-2.5 text-center">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <label htmlFor="signup-username" className="block text-xs font-semibold tracking-wide text-white/60">
                Username
              </label>
              <div className="relative">
                <FaUser className="absolute left-4 top-1/2 -translate-y-1/2 text-white/30 text-xs" />
                <input
                  id="signup-username"
                  name="username"
                  type="text"
                  autoComplete="username"
                  required
                  placeholder="Choose username"
                  value={form.username}
                  onChange={(e) => setForm({ ...form, username: e.target.value })}
                  className="w-full rounded-xl glass-input pl-10 pr-4 py-3 text-xs outline-none focus:border-white focus:bg-white/[0.06]"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <label htmlFor="signup-email" className="block text-xs font-semibold tracking-wide text-white/60">
                Email Address
              </label>
              <div className="relative">
                <FaEnvelope className="absolute left-4 top-1/2 -translate-y-1/2 text-white/30 text-xs" />
                <input
                  id="signup-email"
                  name="email"
                  type="email"
                  autoComplete="email"
                  required
                  placeholder="hello@hangout.com"
                  value={form.email}
                  onChange={(e) => setForm({ ...form, email: e.target.value })}
                  className="w-full rounded-xl glass-input pl-10 pr-4 py-3 text-xs outline-none focus:border-white focus:bg-white/[0.06]"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <label htmlFor="signup-password" className="block text-xs font-semibold tracking-wide text-white/60">
                Password
              </label>
              <div className="relative">
                <FaLock className="absolute left-4 top-1/2 -translate-y-1/2 text-white/30 text-xs" />
                <input
                  id="signup-password"
                  name="password"
                  type="password"
                  autoComplete="new-password"
                  required
                  placeholder="At least 6 characters"
                  value={form.password}
                  onChange={(e) => setForm({ ...form, password: e.target.value })}
                  className="w-full rounded-xl glass-input pl-10 pr-4 py-3 text-xs outline-none focus:border-white focus:bg-white/[0.06]"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <label htmlFor="signup-confirm" className="block text-xs font-semibold tracking-wide text-white/60">
                Confirm Password
              </label>
              <div className="relative">
                <FaLock className="absolute left-4 top-1/2 -translate-y-1/2 text-white/30 text-xs" />
                <input
                  id="signup-confirm"
                  name="confirm"
                  type="password"
                  autoComplete="new-password"
                  required
                  placeholder="Re-enter password"
                  value={form.confirm}
                  onChange={(e) => setForm({ ...form, confirm: e.target.value })}
                  className="w-full rounded-xl glass-input pl-10 pr-4 py-3 text-xs outline-none focus:border-white focus:bg-white/[0.06]"
                />
              </div>
            </div>

            <div className="flex items-start gap-2 text-[10px] text-white/50 pt-1">
              <input id="terms" type="checkbox" required className="mt-0.5 h-3.5 w-3.5 rounded border border-white/20 bg-black/40 cursor-pointer" />
              <label htmlFor="terms" className="leading-snug cursor-pointer select-none">
                I agree to the <a href="#" className="text-white hover:underline">Terms of Use</a> and <a href="#" className="text-white hover:underline">Privacy Policy</a>.
              </label>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full glass-btn-primary py-3 rounded-full text-xs font-semibold flex items-center justify-center gap-2 disabled:opacity-50 mt-2"
            >
              {loading ? "Creating account…" : "Create Account"}
              <FaArrowRight size={10} />
            </button>
          </form>

          <p className="text-xs text-center text-white/50">
            Already have an account?{" "}
            <Link to="/login" className="text-white hover:underline font-semibold transition-colors">Log In</Link>.
          </p>
        </div>
      </main>
    </div>
  );
}
