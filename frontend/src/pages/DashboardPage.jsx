import { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../AuthContext";
import { useSocket } from "../SocketContext";
import { useToastHelpers } from "../Toast";
// sendDirectChatRequest comes from useSocket
import {
  getInterests, setInterests as apiSetInterests,
  getProfile, getSuggestedUsers, followToggle,
} from "../api";

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
  const { unreadCount, markNotificationsRead, sendDirectChatRequest } = useSocket();
  const toast    = useToastHelpers();
  const navigate = useNavigate();

  const [profileMenuOpen, setProfileMenuOpen] = useState(false);
  const [micOn, setMicOn]   = useState(true);
  const [camOn, setCamOn]   = useState(true);
  const [interests, setInterests]       = useState([]);
  const [interestInput, setInterestInput] = useState("");
  const [loadingInterests, setLoadingInterests] = useState(true);
  const [friends, setFriends]           = useState([]);
  const [rankScore, setRankScore]       = useState(0);
  const [suggested, setSuggested]       = useState([]);
  const [followingIds, setFollowingIds] = useState(new Set());

  useEffect(() => {
    Promise.all([getInterests(), getProfile(), getSuggestedUsers()])
      .then(([intData, profile, sugg]) => {
        setInterests(parseInterests(intData.interests));
        setFriends(profile.friends || []);
        setRankScore(profile.rank?.count ?? 0);
        const followingSet = new Set(
          (profile.following || []).map((f) => typeof f === "string" ? f : f._id || f.id)
        );
        setFollowingIds(followingSet);
        setSuggested(Array.isArray(sugg) ? sugg.slice(0, 6) : []);
      })
      .catch(() => {})
      .finally(() => setLoadingInterests(false));
  }, []);

  const addInterest = async () => {
    const tag = interestInput.trim().replace(/^#/, "");
    if (!tag) return;
    const updated = [...new Set([...interests, tag])];
    setInterests(updated);
    setInterestInput("");
    try {
      await apiSetInterests(updated);
      toast.success("Interest saved!");
    } catch {
      toast.error("Failed to save interest");
    }
  };

  const removeInterest = async (tag) => {
    const updated = interests.filter((t) => t !== tag);
    setInterests(updated);
    try {
      await apiSetInterests(updated);
      toast.notif(`Removed #${tag}`);
    } catch {}
  };

  const handleFollowSuggested = async (uid) => {
    try {
      const result = await followToggle(uid);
      const isNowFollowing = result?.message?.includes("Followed");
      setFollowingIds((prev) => {
        const next = new Set(prev);
        if (isNowFollowing) next.add(uid);
        else next.delete(uid);
        return next;
      });
      setSuggested((prev) =>
        prev.map((u) => (u._id || u.id) === uid ? { ...u, isFollowing: isNowFollowing } : u)
      );
      if (isNowFollowing) toast.follow(`Now following ${result?.targetUserId ? "" : "user"}`);
      if (result?.isFriend) toast.friend("You're now friends! 🎉");
    } catch (err) {
      toast.error(err.message || "Failed");
    }
  };

  const startFriendChat = (friend) => {
    const fid   = typeof friend === "string" ? friend : friend._id || friend.id;
    const fname = typeof friend === "string" ? friend : friend.username || "Friend";
    // Send a direct chat request — friend gets an Accept/Decline toast
    const room = sendDirectChatRequest(fid, fname);
    if (room) {
      // Navigate to chat page in "waiting_accept" mode
      navigate("/chat", { state: { friendId: fid, friendName: fname, directRoom: room } });
    }
  };

  const handleLogout = async () => {
    await logout();
    navigate("/login");
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
            {/* Notification bell */}
            <button
              onClick={() => { markNotificationsRead(); navigate("/settings"); }}
              className="relative h-8 w-8 flex items-center justify-center rounded-full border border-white/20 hover:bg-white/10 transition"
            >
              🔔
              {unreadCount > 0 && (
                <span className="absolute -top-1 -right-1 h-4 w-4 rounded-full bg-red-500 text-[9px] font-bold flex items-center justify-center">
                  {unreadCount > 9 ? "9+" : unreadCount}
                </span>
              )}
            </button>
            <Link to="/feed" className="bg-gray-800 px-4 py-1.5 rounded-full hover:bg-white hover:text-black transition">Feed</Link>
            <Link to="/post" className="bg-gray-800 px-4 py-1.5 rounded-full hover:bg-white hover:text-black transition">Post</Link>
          </div>
        </div>
      </header>

      {/* Body */}
      <main className="flex-1 min-h-0 px-2 sm:px-4 lg:px-6 py-4 flex gap-3 sm:gap-4 overflow-hidden">

        {/* ── Left sidebar ─────────────────────────────────────────── */}
        <aside className="w-56 sm:w-64 flex-shrink-0 flex flex-col bg-white/5 border border-white/10 rounded-2xl overflow-hidden">
          <div className="flex-shrink-0 p-3 border-b border-white/10">
            <div className="text-xs font-semibold text-gray-100">Quick links</div>
          </div>
          <div className="flex-1 min-h-0 overflow-y-auto px-2 py-2 space-y-1">
            <Link to="/chat-history"
              className="flex items-center gap-2 rounded-xl px-2.5 py-2 hover:bg-white/10 transition text-xs font-medium">
              <span>🗂</span> Chat History
            </Link>
            <Link to="/feed"
              className="flex items-center gap-2 rounded-xl px-2.5 py-2 hover:bg-white/10 transition text-xs font-medium">
              <span>📰</span> Community Feed
            </Link>
            <Link to="/post"
              className="flex items-center gap-2 rounded-xl px-2.5 py-2 hover:bg-white/10 transition text-xs font-medium">
              <span>✏️</span> Post Something
            </Link>
            <Link to="/settings"
              className="flex items-center gap-2 rounded-xl px-2.5 py-2 hover:bg-white/10 transition text-xs font-medium">
              <span>⚙️</span> Settings
            </Link>
          </div>

          {/* Rank */}
          <div className="flex-shrink-0 border-t border-white/10 px-3 py-2 flex items-center justify-between">
            <span className="text-[11px] text-gray-400">Your rank</span>
            <span className="text-sm font-bold text-yellow-400">★ {rankScore}</span>
          </div>

          {/* Profile button */}
          <div className="flex-shrink-0 relative border-t border-white/10 px-3 py-2.5">
            <button
              onClick={(e) => { e.stopPropagation(); setProfileMenuOpen(!profileMenuOpen); }}
              className="flex items-center gap-2 text-xs w-full text-left"
            >
              <div className="h-9 w-9 flex-shrink-0 rounded-full bg-white text-black flex items-center justify-center font-bold text-sm">
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
                <button onClick={handleLogout}
                  className="text-left px-3 py-2 text-red-300 hover:bg-white/5 transition-colors">
                  Logout
                </button>
              </div>
            )}
          </div>
        </aside>

        {/* ── Center ───────────────────────────────────────────────── */}
        <section className="flex-1 min-w-0 flex flex-col bg-white/5 border border-white/50 rounded-2xl backdrop-blur-xl overflow-hidden px-4 sm:px-6 py-5 gap-4">
          <div className="flex-shrink-0">
            <h2 className="text-sm sm:text-base font-semibold">Your Hangout space</h2>
            <p className="text-[11px] sm:text-xs text-gray-300 mt-0.5">Add interests, then hit Go to start searching.</p>
          </div>

          {/* Interests */}
          <div className="flex-shrink-0 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-semibold uppercase tracking-[0.2em]">Interests</h3>
              <span className="text-[11px] text-gray-400">Used for matching</span>
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

          {/* Go button */}
          <div className="flex-1 min-h-0 flex flex-col items-center justify-center gap-4">
            <Link to="/chat"
              className="w-24 h-24 sm:w-28 sm:h-28 rounded-full bg-white text-black text-xl sm:text-2xl font-semibold flex items-center justify-center hover:scale-105 hover:bg-gray-100 transition-transform shadow-[0_0_40px_rgba(255,255,255,0.25)]">
              Go
            </Link>
            <div className="flex flex-wrap items-center justify-center gap-3">
              <button onClick={() => setMicOn(!micOn)}
                className={`px-4 py-1.5 rounded-full text-xs border flex items-center gap-1.5 transition ${
                  micOn ? "bg-white text-black border-white" : "bg-black/60 text-white border-white/30"
                }`}>
                <span>🎙</span><span>{micOn ? "Mic enabled" : "Mic muted"}</span>
              </button>
              <button onClick={() => setCamOn(!camOn)}
                className={`px-4 py-1.5 rounded-full text-xs border flex items-center gap-1.5 transition ${
                  camOn ? "bg-white text-black border-white" : "bg-black/60 text-white border-white/30"
                }`}>
                <span>📹</span><span>{camOn ? "Video enabled" : "Video disabled"}</span>
              </button>
            </div>
            <p className="text-[11px] text-gray-300 text-center">
              {interests.length > 0
                ? `Matching on: ${interests.map((i) => `#${i}`).join(" ")}`
                : "Ready to start a Hangout."}
            </p>
          </div>
        </section>

        {/* ── Right sidebar – Friends + Suggested ──────────────────── */}
        <aside className="w-56 sm:w-64 flex-shrink-0 hidden md:flex flex-col bg-white/5 border border-white/10 rounded-2xl overflow-hidden">
          <div className="flex-shrink-0 px-3 py-3 border-b border-white/10">
            <div className="text-xs font-semibold uppercase tracking-[0.2em]">Friends</div>
            <div className="text-[11px] text-gray-400">Mutual follows · click to chat</div>
          </div>

          <div className="flex-1 min-h-0 overflow-y-auto px-2 py-2 space-y-1">
            {friends.length === 0 ? (
              <div className="text-[11px] text-gray-500 px-2 py-6 text-center">
                <span className="text-2xl block mb-1">🤝</span>
                <p>No friends yet.</p>
                <p className="text-[10px] mt-1 text-gray-600">Follow back and you'll become friends!</p>
              </div>
            ) : (
              friends.map((f, i) => {
                const name     = typeof f === "string" ? f : f.username || "User";
                const fInitial = name[0]?.toUpperCase() || "U";
                const isOnline = typeof f === "object" ? f.isOnline : false;
                return (
                  <div key={i}
                    onClick={() => startFriendChat(f)}
                    className="flex items-center gap-2 rounded-xl px-2.5 py-2 hover:bg-white/10 transition cursor-pointer group">
                    <div className="relative flex-shrink-0">
                      <div className="h-8 w-8 rounded-full bg-white text-black flex items-center justify-center text-xs font-bold">
                        {fInitial}
                      </div>
                      {isOnline && (
                        <span className="absolute bottom-0 right-0 h-2 w-2 rounded-full bg-green-400 border border-black" />
                      )}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-xs font-semibold truncate">{name}</div>
                      <div className="text-[10px] text-gray-500">
                        {isOnline ? <span className="text-green-400">Online</span> : "Click to chat"}
                      </div>
                    </div>
                    <span className="text-gray-600 group-hover:text-white text-xs transition">→</span>
                  </div>
                );
              })
            )}
          </div>

          {/* Suggested */}
          {suggested.length > 0 && (
            <>
              <div className="flex-shrink-0 px-3 py-2 border-t border-white/10">
                <div className="text-[11px] font-semibold text-gray-400 uppercase tracking-widest">Suggested</div>
              </div>
              <div className="flex-shrink-0 px-2 pb-2 space-y-1">
                {suggested.map((u, i) => {
                  const uid  = u._id || u.id;
                  const name = u.username || "User";
                  const isF  = followingIds.has(uid?.toString());
                  return (
                    <div key={i} className="flex items-center gap-2 px-2 py-1.5 rounded-xl hover:bg-white/5 transition">
                      <div className="h-7 w-7 flex-shrink-0 rounded-full bg-white/20 text-white flex items-center justify-center text-xs font-bold">
                        {name[0]?.toUpperCase()}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="text-xs font-semibold truncate">{name}</div>
                        {u.commonCount > 0 && (
                          <div className="text-[9px] text-gray-500">{u.commonCount} common interest{u.commonCount !== 1 ? "s" : ""}</div>
                        )}
                      </div>
                      <button onClick={() => handleFollowSuggested(uid?.toString())}
                        className={`flex-shrink-0 text-[10px] px-2 py-0.5 rounded-full border transition ${
                          isF ? "border-white/30 text-gray-400 hover:border-red-400 hover:text-red-400"
                              : "border-white text-white hover:bg-white hover:text-black"
                        }`}>
                        {isF ? "✓" : "+"}
                      </button>
                    </div>
                  );
                })}
              </div>
            </>
          )}
        </aside>
      </main>
    </div>
  );
}
