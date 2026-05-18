import { Link } from "react-router-dom";
import { FaArrowRight, FaCompass, FaLock, FaUserFriends } from "react-icons/fa";

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-[#030303] text-white antialiased flex flex-col relative overflow-hidden">
      {/* Background radial glow */}
      <div className="absolute top-[-20%] left-[-10%] w-[60%] h-[60%] rounded-full bg-blue-500/10 blur-[120px] pointer-events-none pulse-glow-bg" />
      <div className="absolute bottom-[-20%] right-[-10%] w-[60%] h-[60%] rounded-full bg-rose-500/5 blur-[120px] pointer-events-none pulse-glow-bg" style={{ animationDelay: "-3s" }} />

      <header className="w-full border-b border-white/5 bg-black/20 backdrop-blur-md z-10">
        <div className="max-w-5xl mx-auto px-6 py-5 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="h-6 w-6 rounded-lg bg-white flex items-center justify-center font-black text-black text-xs tracking-wider">H</div>
            <span className="font-bold tracking-tight text-sm text-white/90">Hangout</span>
          </div>
          <nav className="flex items-center gap-6 text-xs text-white/50">
            <a href="#" className="hover:text-white transition-colors">About</a>
            <a href="#" className="hover:text-white transition-colors">Privacy</a>
          </nav>
        </div>
      </header>

      <main className="flex-1 flex flex-col items-center justify-center px-6 py-20 z-10 max-w-4xl mx-auto text-center space-y-12">
        <div className="space-y-6">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-white/5 border border-white/10 text-[11px] font-semibold uppercase tracking-widest text-white/60">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            Vibe-matching live now
          </div>
          
          <h1 className="text-5xl sm:text-6xl md:text-7xl font-extrabold tracking-tight bg-gradient-to-b from-white via-white to-white/45 bg-clip-text text-transparent leading-none py-1">
            Meet real people.<br/>Instantly.
          </h1>
          
          <p className="text-sm sm:text-base text-white/60 leading-relaxed max-w-xl mx-auto font-light">
            Hangout instantly pairs you with real people around the world who
            match your vibe. No pressure, no curated profiles—just raw, real-time
            conversations.
          </p>
        </div>

        {/* Feature Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 w-full max-w-2xl pt-4">
          <div className="glass-panel-light rounded-2xl p-5 text-left space-y-2">
            <FaCompass className="text-white/80 text-lg" />
            <h3 className="text-xs font-bold tracking-wide uppercase text-white/90">Instant Match</h3>
            <p className="text-[11px] text-white/50 leading-relaxed">No profiles or left swipes. Enter your interests and connect immediately.</p>
          </div>
          <div className="glass-panel-light rounded-2xl p-5 text-left space-y-2">
            <FaUserFriends className="text-white/80 text-lg" />
            <h3 className="text-xs font-bold tracking-wide uppercase text-white/90">Direct Friends</h3>
            <p className="text-[11px] text-white/50 leading-relaxed">Follow users you vibe with to become friends and start calls anytime.</p>
          </div>
          <div className="glass-panel-light rounded-2xl p-5 text-left space-y-2">
            <FaLock className="text-white/80 text-lg" />
            <h3 className="text-xs font-bold tracking-wide uppercase text-white/90">Privacy First</h3>
            <p className="text-[11px] text-white/50 leading-relaxed">Video calls require explicit consent. You remain in absolute control.</p>
          </div>
        </div>

        <div className="pt-4">
          <Link
            to="/login"
            className="glass-btn-primary inline-flex items-center justify-center gap-2 px-10 py-3.5 rounded-full text-sm font-semibold tracking-wide"
          >
            Start Hangout
            <FaArrowRight size={12} />
          </Link>
        </div>
      </main>
    </div>
  );
}
