import { Link } from "react-router-dom";

export default function ForgotPasswordPage() {
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
            <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight">
              Forgot your password?
            </h1>
            <p className="text-xs sm:text-sm text-white/60">
              Enter the email you use for Hangout. We'll send a link to reset your password.
            </p>
          </div>

          <form onSubmit={(e) => e.preventDefault()} className="space-y-5">
            <div className="space-y-1.5">
              <label htmlFor="reset-email" className="block text-xs font-medium tracking-wide text-white/70">
                Email address
              </label>
              <input
                id="reset-email"
                name="email"
                type="email"
                required
                placeholder="tempemail@example.com"
                defaultValue="tempemail@example.com"
                className="w-full rounded-xl bg-black/40 border border-white/20 px-3 py-2.5 text-sm outline-none focus:border-white focus:bg-black/60 transition-colors"
              />
            </div>

            <button
              type="submit"
              className="w-full mt-1 inline-flex items-center justify-center rounded-full bg-white text-black text-sm font-semibold py-2.5 border border-white hover:bg-black hover:text-white transition-colors"
            >
              Send reset email
            </button>
          </form>

          <p className="text-xs text-center text-white/60">
            Remembered your password?{" "}
            <Link to="/login" className="text-white hover:underline font-medium">
              Back to login
            </Link>
            .
          </p>
        </div>
      </main>
    </div>
  );
}
