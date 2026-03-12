import { useState } from "react";
import { Link, useNavigate, Navigate } from "react-router-dom";
import { signup } from "../api";
import { useAuth } from "../AuthContext";
import { useToastHelpers } from "../Toast";

export default function SignupPage() {
  const navigate = useNavigate();
  const { setUser, user } = useAuth();

  if (user) return <Navigate to="/dashboard" replace />;
  const [form, setForm] = useState({ username: "", email: "", password: "", confirm: "" });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    if (form.password !== form.confirm) {
      setError("Passwords do not match");
      return;
    }
    setLoading(true);
    try {
      const data = await signup({ username: form.username, email: form.email, password: form.password });
      setUser(data.user || data);
      navigate("/dashboard");
    } catch (err) {
      setError(err.message || "Signup failed");
    } finally {
      setLoading(false);
    }
  };

  const field = (name) => ({
    value: form[name],
    onChange: (e) => setForm({ ...form, [name]: e.target.value }),
  });

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
            <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight">Create your account</h1>
            <p className="text-xs sm:text-sm text-white/60">
              Join Hangout and start connecting with people in seconds.
            </p>
          </div>

          {error && (
            <div className="text-xs text-red-400 bg-red-400/10 border border-red-400/20 rounded-xl px-3 py-2 text-center">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-5">
            {[
              { id: "signup-username", label: "Username", name: "username", type: "text", autoComplete: "username" },
              { id: "signup-email", label: "Email", name: "email", type: "email", autoComplete: "email" },
              { id: "signup-password", label: "Password", name: "password", type: "password", autoComplete: "new-password" },
              { id: "signup-confirm", label: "Confirm password", name: "confirm", type: "password", autoComplete: "new-password" },
            ].map((f) => (
              <div key={f.id} className="space-y-1.5">
                <label htmlFor={f.id} className="block text-xs font-medium tracking-wide text-white/70">
                  {f.label}
                </label>
                <input
                  id={f.id}
                  name={f.name}
                  type={f.type}
                  autoComplete={f.autoComplete}
                  required
                  {...field(f.name)}
                  className="w-full rounded-xl bg-black/40 border border-white/20 px-3 py-2.5 text-sm outline-none focus:border-white focus:bg-black/60 transition-colors"
                />
              </div>
            ))}

            <div className="flex items-start gap-2 text-[11px] text-white/60">
              <input id="terms" type="checkbox" required className="mt-0.5 h-3.5 w-3.5 rounded border border-white/30 bg-black/60" />
              <label htmlFor="terms" className="leading-snug">
                I agree to the{" "}
                <a href="#" className="text-white hover:underline">Terms of Use</a> and{" "}
                <a href="#" className="text-white hover:underline">Privacy Policy</a>.
              </label>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full mt-1 inline-flex items-center justify-center rounded-full bg-white text-black text-sm font-semibold py-2.5 border border-white hover:bg-black hover:text-white transition-colors disabled:opacity-50"
            >
              {loading ? "Creating account…" : "Sign up"}
            </button>
          </form>

          <p className="text-xs text-center text-white/60">
            Already have an account?{" "}
            <Link to="/login" className="text-white hover:underline font-medium">Log in</Link>.
          </p>
        </div>
      </main>
    </div>
  );
}
