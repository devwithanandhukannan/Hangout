import { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../AuthContext";
import { getInterests, setInterests as apiSetInterests, getProfile } from "../api";

function parseInterests(raw) {
  if (!raw) return [];
  if (typeof raw === "string") return raw.split(",").map((s) => s.trim()).filter(Boolean);
  if (Array.isArray(raw))
    return raw.flatMap((item) => (typeof item === "string" ? item.split(",") : [item]))
              .map((s) => s.trim()).filter(Boolean);
  return [];
}

export default function DashboardPage() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [profileMenuOpen, setProfileMenuOpen] = useState(false);
  const [micOn, setMicOn]     = useState(true);
  const [camOn, setCamOn]     = useState(true);
  const [interests, setInterests]       = useState([]);
  const [interestInput, setInterestInput] = useState("");
  const [interestStatus, setInterestStatus] = useState("");
  const [loadingInterests, setLoadingInterests] = useState(true);
  const [friends, setFriends] = useState([]);

  useEffect(() => {
    getInterests()
      .then((d) => setInterests(parseInterests(d.interests)))
      .catch(() => setInterests([]))
      .finally(() => setLoadingInterests(false));

    getProfile()
      .then((d) => { const p = d.user || d; setFriends(p.friends || p.following || []); })
      .catch(() => setFriends([]));
  }, []);

  const addInterest = async () => {
    const tag = interestInput.trim().replace(/^#/, "");
    if (!tag) return;
    const updated = [...new Set([...interests, tag])];
    setInterests(updated);
    setInterestInput("");
    try {
      await apiSetInterests(updated.join(", "));
      setInterestStatus("Saved!");
    } catch { setInterestStatus("Failed"); }
    setTimeout(() => setInterestStatus(""), 2000);
  };

  const removeInterest = async (tag) => {
    const updated = interests.filter((t) => t !== tag);
    setInterests(updated);
    try { await apiSetInterests(updated.join(", ")); } catch {}
  };

  const initial     = user?.username?.[0]?.toUpperCase() || "U";
  const displayName = user?.username || "User";
  const handle      = `@${user?.username || "user"}`;

  return (
    <div
      className="h-screen flex flex-col bg-black text-white antialiased overflow-hidden"
      onClick={() => setProfileMenuOpen(false)}
    >
      {/* Header */}
      <header className="flex-shrink-0 border-b border-white/10 bg-black/60 backdrop-blur">
        <div className="px-4 sm:px-6 lg:px-8 py-3 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="font-semibold tracking-tight text-sm sm:text-base">Hangout &gt;</span>
            <span className="text-xs sm:text-sm text-gray-300">Dashboard</span>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <Link to="/feed" className="bg-gray-800 px-4 py-1.5 rounded-full hover:bg-white hover:text-black transition">Feed</Link>
            <Link to="/post" className="bg-gray-800 px-4 py-1.5 rounded-full hover:bg-white hover:text-black transition">Post</Link>
          </div>
        </div>
      </header>

      {/* Body */}
      <main className="flex-1 min-h-0 px-2 sm:px-4 lg:px-6 py-4 flex gap-3 sm:gap-4 overflow-hidden">

        {/* ── Left sidebar ─────────────────────────────────────────────── */}
        <aside className="w-56 sm:w-64 flex-shrink-0 flex flex-col bg-white/5 border border-white/10 rounded-2xl overflow-hidden">
          <div className="flex-shrink-0 p-3 border-b border-white/10">
            <div className="text-xs font-semibold text-gray-100">Interest history</div>
          </div>

          <Link
            to="/chat-history"
            className="flex-1 flex flex-col items-center justify-center gap-2 text-[11px] text-gray-400 hover:text-white hover:bg-white/5 transition px-4 text-center"
          >
            <span className="text-2xl">🗂</span>
            View your chat history
          </Link>

          {/* Profile */}
          <div className="flex-shrink-0 relative border-t border-white/10 px-3 py-2.5">
            <button
              onClick={(e) => { e.stopPropagation(); setProfileMenuOpen(!profileMenuOpen); }}
              className="flex items-center gap-2 text-xs w-full text-left"
            >
              <div className="h-9 w-9 flex-shrink-0 rounded-full bg-white text-black flex items-center justify-center font-semibold text-sm">
                {initial}
              </div>
              <div className="flex-1 min-w-0">
                <div className="font-semibold text-gray-50 truncate">{displayName}</div>
                <div className="text-[11px] text-gray-400 truncate">{handle}</div>
              </div>
              <span className="text-gray-400">⋮</span>
            </button>

            {profileMenuOpen && (
              <div className="absolute bottom-full mb-1 left-3 w-40 bg-black border border-white/10 rounded-xl shadow-lg text-xs overflow-hidden flex flex-col z-50">
                <Link to="/settings" className="px-3 py-2 hover:bg-white/5 transition-colors">Settings</Link>
                <button
                  onClick={() => { logout(); navigate("/"); }}
                  className="text-left px-3 py-2 text-red-300 hover:bg-white/5 transition-colors"
                >Logout</button>
              </div>
            )}
          </div>
        </aside>

        {/* ── Center ───────────────────────────────────────────────────── */}
        <section className="flex-1 min-w-0 flex flex-col bg-white/5 border border-white/50 rounded-2xl backdrop-blur-xl overflow-hidden px-4 sm:px-6 py-5 gap-5">
          <div className="flex-shrink-0">
            <h2 className="text-sm sm:text-base font-semibold">Your Hangout space</h2>
            <p className="text-[11px] sm:text-xs text-gray-300 mt-0.5">Add interests, then hit Go to start searching.</p>
          </div>

          {/* Interests */}
          <div className="flex-shrink-0 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-semibold uppercase tracking-[0.2em]">Interests</h3>
              <span className="text-[11px] text-gray-400">Use <span className="font-mono">#</span> tags</span>
            </div>

            <div className="flex gap-2 flex-wrap">
              <input
                type="text"
                placeholder="#movies #gaming #music"
                value={interestInput}
                onChange={(e) => setInterestInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && addInterest()}
                className="flex-1 min-w-[140px] rounded-xl bg-black/60 border border-white/20 px-3 py-2 text-xs outline-none focus:border-white placeholder:text-gray-500"
              />
              <button onClick={addInterest}
                className="px-4 py-2 rounded-xl text-xs font-semibold bg-white text-black hover:bg-gray-100 transition">
                Add
              </button>
            </div>

            {interestStatus && <p className="text-[11px] text-green-400">{interestStatus}</p>}

            <div className="flex flex-wrap gap-2 text-[11px]">
              {loadingInterests ? (
                <span className="text-gray-500">Loading…</span>
              ) : interests.length === 0 ? (
                <span className="text-gray-500">No interests yet. Add some!</span>
              ) : (
                interests.map((tag) => (
                  <span key={tag} onClick={() => removeInterest(tag)} title="Click to remove"
                    className="inline-flex items-center gap-1 px-3 py-1 rounded-full bg-white/5 border border-white/20 cursor-pointer hover:border-red-400/60 transition">
                    #{tag}
                    <span className="text-gray-500 hover:text-red-400 text-[10px]">✕</span>
                  </span>
                ))
              )}
            </div>
          </div>

          {/* Go */}
          <div className="flex-1 min-h-0 flex flex-col items-center justify-center gap-4">
            <Link to="/chat"
              className="w-24 h-24 sm:w-28 sm:h-28 rounded-full bg-white text-black text-xl sm:text-2xl font-semibold flex items-center justify-center hover:scale-105 hover:bg-gray-100 transition-transform shadow-[0_0_40px_rgba(255,255,255,0.25)]">
              Go
            </Link>

            <div className="flex flex-wrap items-center justify-center gap-3">
              <button onClick={() => setMicOn(!micOn)}
                className={`px-4 py-1.5 rounded-full text-xs border flex items-center gap-1.5 transition ${micOn ? "bg-white text-black border-white" : "bg-black/60 text-white border-white/30"}`}>
                <span>🎙</span><span>{micOn ? "Mic enabled" : "Mic muted"}</span>
              </button>
              <button onClick={() => setCamOn(!camOn)}
                className={`px-4 py-1.5 rounded-full text-xs border flex items-center gap-1.5 transition ${camOn ? "bg-white text-black border-white" : "bg-black/60 text-white border-white/30"}`}>
                <span>📹</span><span>{camOn ? "Video enabled" : "Video disabled"}</span>
              </button>
            </div>

            <p className="text-[11px] text-gray-300 text-center">
              {interests.length > 0 ? `Matching on: ${interests.map((i) => `#${i}`).join(" ")}` : "Ready to start a Hangout."}
            </p>
          </div>
        </section>

        {/* ── Right sidebar – Friends ───────────────────────────────────── */}
        <aside className="w-56 sm:w-64 flex-shrink-0 hidden md:flex flex-col bg-white/5 border border-white/10 rounded-2xl overflow-hidden">
          <div className="flex-shrink-0 px-3 py-3 border-b border-white/10">
            <div className="text-xs font-semibold uppercase tracking-[0.2em]">Friends</div>
            <div className="text-[11px] text-gray-400">Who's around right now</div>
          </div>

          {friends.length === 0 ? (
            <div className="flex-1 flex items-center justify-center text-[11px] text-gray-500 px-3 text-center">
              No friends yet. Follow people to connect!
            </div>
          ) : (
            <div className="flex-1 min-h-0 overflow-y-auto px-2 py-2 space-y-1">
              {friends.map((f, i) => {
                const name = typeof f === "string" ? f : f.username || "User";
                return (
                  <div key={i} className="flex items-center gap-2 rounded-xl px-2.5 py-2 hover:bg-white/10 transition">
                    <div className="h-8 w-8 flex-shrink-0 rounded-full bg-white text-black flex items-center justify-center text-xs font-semibold">
                      {name[0]?.toUpperCase() || "U"}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-xs font-semibold truncate">{name}</div>
                    </div>
                    <div className="h-1.5 w-1.5 flex-shrink-0 rounded-full bg-gray-400" />
                  </div>
                );
              })}
            </div>
          )}
        </aside>
      </main>
    </div>
  );
}
