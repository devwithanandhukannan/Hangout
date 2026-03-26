import { Link } from "react-router-dom";

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-black text-white antialiased flex flex-col">
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
        <section className="text-center max-w-xl mx-auto space-y-6">
          <div className="space-y-3">
            <h1 className="text-4xl sm:text-5xl md:text-6xl font-extrabold tracking-tight">
              Hangout
            </h1>
            <p className="text-xs sm:text-sm font-medium uppercase tracking-[0.35em] text-white/60">
              Connect • Chat • Discover
            </p>
          </div>

          <p className="text-sm sm:text-base text-white/70 leading-relaxed">
            Hangout instantly pairs you with real people around the world who
            match your vibe. No profiles, no pressure—just raw, real-time
            conversations. Tap{" "}
            <span className="text-white font-semibold">start</span> and see who's on
            the other side.
          </p>

          <div className="pt-2">
            <Link
              to="/login"
              className="inline-flex items-center justify-center px-10 py-3 rounded-full bg-white text-black text-sm sm:text-base font-semibold tracking-wide border border-white hover:bg-black hover:text-white transition-colors"
            >
              Start
            </Link>
          </div>
        </section>
      </main>
    </div>
  );
}
