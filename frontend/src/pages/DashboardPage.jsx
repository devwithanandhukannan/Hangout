import { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../AuthContext";
import { useSocket } from "../SocketContext";
import { useToastHelpers } from "../Toast";
import { FaBell, FaHistory, FaUserFriends, FaHome, FaStar, FaSignOutAlt, FaTimes, FaPlus } from "react-icons/fa";
import { CgCamera, CgCommunity, CgMic } from "react-icons/cg";
import { IoIosAddCircle, IoIosSettings } from "react-icons/io";
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
  const toast = useToastHelpers();
  const navigate = useNavigate();

  const [profileMenuOpen, setProfileMenuOpen] = useState(false);
  const [micOn, setMicOn] = useState(true);
  const [camOn, setCamOn] = useState(true);
  const [interests, setInterests] = useState([]);
  const [interestInput, setInterestInput] = useState("");
  const [loadingInterests, setLoadingInterests] = useState(true);
  const [friends, setFriends] = useState([]);
  const [rankScore, setRankScore] = useState(0);
  const [suggested, setSuggested] = useState([]);
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
      .catch(() => { })
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
    } catch { }
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
      if (isNowFollowing) toast.follow(`Now following user`);
      if (result?.isFriend) toast.friend("You are now friends!");
    } catch (err) {
      toast.error(err.message || "Failed");
    }
  };

  const startFriendChat = (friend) => {
    const fid = typeof friend === "string" ? friend : friend._id || friend.id;
    const fname = typeof friend === "string" ? friend : friend.username || "Friend";
    const room = sendDirectChatRequest(fid, fname);
    if (room) {
      navigate("/chat", { state: { friendId: fid, friendName: fname, directRoom: room } });
    }
  };

  const handleLogout = async () => {
    await logout();
    navigate("/login");
  };

  const initial = user?.username?.[0]?.toUpperCase() || "U";
  const displayName = user?.username || "User";
  const handle = `@${user?.username || "user"}`;

  return (
    <div
      className="h-screen flex flex-col bg-[#030303] text-white antialiased overflow-hidden pb-20 md:pb-0"
      onClick={() => setProfileMenuOpen(false)}
    >
      {/* Background glow elements */}
      <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] rounded-full bg-blue-500/5 blur-[120px] pointer-events-none pulse-glow-bg" />
      <div className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] rounded-full bg-rose-500/5 blur-[120px] pointer-events-none pulse-glow-bg" style={{ animationDelay: "-3s" }} />

      {/* Modern minimal glass header */}
      <header className="flex-shrink-0 border-b border-white/5 bg-black/30 backdrop-blur-md z-30">
        <div className="px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="h-6 w-6 rounded-lg bg-white flex items-center justify-center font-black text-black text-xs tracking-wider">H</div>
            <span className="font-bold tracking-tight text-sm text-white/90">Hangout</span>
          </div>

          <div className="flex items-center gap-4">
            {/* Notification bell */}
            <button
              onClick={() => { markNotificationsRead(); navigate("/settings"); }}
              className="relative h-9 w-9 flex items-center justify-center rounded-xl bg-white/5 border border-white/10 hover:bg-white/12 transition-colors"
            >
              <FaBell className="text-white/70 text-xs" />
              {unreadCount > 0 && (
                <span className="absolute -top-1.5 -right-1.5 h-4.5 w-4.5 rounded-full bg-rose-500 text-[9px] font-bold flex items-center justify-center border border-black">
                  {unreadCount > 9 ? "9+" : unreadCount}
                </span>
              )}
            </button>
            
            {/* Quick Profile display on header for mobile */}
            <div 
              onClick={(e) => { e.stopPropagation(); setProfileMenuOpen(!profileMenuOpen); }}
              className="h-9 w-9 md:hidden rounded-xl bg-white text-black flex items-center justify-center font-bold text-xs cursor-pointer"
            >
              {initial}
            </div>
          </div>
        </div>
      </header>

      {/* Body */}
      <main className="flex-1 min-h-0 px-4 sm:px-6 py-5 flex gap-5 overflow-hidden max-w-7xl mx-auto w-full z-10">

        {/* ── Left sidebar ─────────────────────────────────────────── */}
        <aside className="w-60 flex-shrink-0 hidden md:flex flex-col glass-panel rounded-3xl overflow-hidden p-4 space-y-6">
          <div className="space-y-1.5">
            <div className="text-[10px] font-bold text-white/40 uppercase tracking-widest px-2.5">Workspace</div>
            <div className="space-y-0.5">
              <Link to="/dashboard"
                className="flex items-center gap-3 rounded-xl px-3 py-2.5 bg-white/5 border border-white/5 text-xs font-semibold text-white transition-all">
                <FaHome className="text-white/80" /> Home
              </Link>
              <Link to="/feed"
                className="flex items-center gap-3 rounded-xl px-3 py-2.5 hover:bg-white/5 text-xs font-semibold text-white/60 hover:text-white transition-all">
                <CgCommunity className="text-white/50" size={15} /> Community Feed
              </Link>
              <Link to="/post"
                className="flex items-center gap-3 rounded-xl px-3 py-2.5 hover:bg-white/5 text-xs font-semibold text-white/60 hover:text-white transition-all">
                <IoIosAddCircle className="text-white/50" size={16} /> Post Something
              </Link>
              <Link to="/chat-history"
                className="flex items-center gap-3 rounded-xl px-3 py-2.5 hover:bg-white/5 text-xs font-semibold text-white/60 hover:text-white transition-all">
                <FaHistory className="text-white/50" size={13} /> Chat History
              </Link>
              <Link to="/settings"
                className="flex items-center gap-3 rounded-xl px-3 py-2.5 hover:bg-white/5 text-xs font-semibold text-white/60 hover:text-white transition-all">
                <IoIosSettings className="text-white/50" size={15} /> Settings
              </Link>
            </div>
          </div>

          <div className="flex-1" />

          {/* Profile / Account Area in sidebar */}
          <div className="border-t border-white/5 pt-4 space-y-4">
            <div className="flex items-center justify-between px-1">
              <span className="text-[10px] font-semibold text-white/40 uppercase tracking-widest">Rank</span>
              <span className="text-xs font-bold text-amber-400 flex items-center gap-1">
                <FaStar size={10} /> {rankScore}
              </span>
            </div>

            <div className="relative">
              <button
                onClick={(e) => { e.stopPropagation(); setProfileMenuOpen(!profileMenuOpen); }}
                className="flex items-center gap-3 text-xs w-full text-left rounded-2xl p-2 bg-white/[0.02] border border-white/5 hover:bg-white/[0.05] transition-all"
              >
                <div className="h-9 w-9 flex-shrink-0 rounded-xl bg-white text-black flex items-center justify-center font-bold text-sm">
                  {initial}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="font-bold text-white truncate">{displayName}</div>
                  <div className="text-[10px] text-white/40 truncate">{handle}</div>
                </div>
                <span className="text-white/30 text-xs">⋮</span>
              </button>

              {profileMenuOpen && (
                <div className="absolute bottom-full mb-2 left-0 right-0 glass-panel rounded-2xl shadow-xl text-xs overflow-hidden flex flex-col z-50 p-1">
                  <Link to="/settings" className="px-3.5 py-2.5 rounded-xl hover:bg-white/5 transition-colors font-medium flex items-center gap-2 text-white/80">
                    <IoIosSettings size={14} /> Profile Settings
                  </Link>
                  <button onClick={handleLogout}
                    className="text-left px-3.5 py-2.5 rounded-xl text-rose-300 hover:bg-rose-500/5 transition-colors font-medium flex items-center gap-2">
                    <FaSignOutAlt size={12} /> Log Out
                  </button>
                </div>
              )}
            </div>
          </div>
        </aside>

        {/* ── Center Matchmaking Workspace ───────────────────────────────── */}
        <section className="flex-1 min-w-0 flex flex-col glass-panel rounded-3xl overflow-hidden p-6 gap-6 relative">
          
          {/* Interests section */}
          <div className="space-y-4">
            <div>
              <h2 className="text-base font-bold text-white/95 tracking-tight">Your Hangout Vibe</h2>
              <p className="text-xs text-white/50">Add hashtag topics you want to talk about.</p>
            </div>

            <div className="space-y-3">
              <div className="flex gap-2">
                <input
                  type="text"
                  placeholder="#gaming, #tech, #music..."
                  value={interestInput}
                  onChange={(e) => setInterestInput(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && addInterest()}
                  className="flex-1 rounded-xl glass-input px-4 py-3 text-xs outline-none focus:border-white"
                />
                <button onClick={addInterest}
                  className="glass-btn px-5 py-3 rounded-xl text-xs font-semibold hover:border-white transition-all flex items-center gap-1.5">
                  <FaPlus size={10} /> Add
                </button>
              </div>

              {/* Tag Cloud */}
              <div className="flex flex-wrap gap-2 max-h-[75px] overflow-y-auto pr-1 no-scrollbar">
                {loadingInterests ? (
                  <span className="text-xs text-white/30">Loading interests...</span>
                ) : interests.length === 0 ? (
                  <span className="text-xs text-white/30">Enter topics to match with the perfect partner.</span>
                ) : (
                  interests.map((tag) => (
                    <span key={tag} onClick={() => removeInterest(tag)} title="Click to remove"
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-white/5 border border-white/10 text-xs text-white/80 cursor-pointer hover:border-rose-500/30 hover:bg-rose-500/5 transition-all">
                      #{tag}
                      <FaTimes className="text-white/30 text-[9px] hover:text-rose-400" />
                    </span>
                  ))
                )}
              </div>
            </div>
          </div>

          <div className="flex-1 flex flex-col items-center justify-center gap-6 py-6 border-t border-white/5">
            {/* Glowing Apple Match Portal Button */}
            <div className="relative group">
              <div className="absolute inset-0 rounded-full bg-white/10 blur-xl opacity-50 group-hover:opacity-75 transition-all group-hover:scale-105" />
              <Link to="/chat"
                className="relative w-32 h-32 rounded-full bg-white text-black text-2xl font-bold flex items-center justify-center group-hover:scale-105 hover:bg-white/95 transition-all shadow-[0_0_40px_rgba(255,255,255,0.2)]">
                Start
              </Link>
            </div>

            {/* Media quick config */}
            <div className="flex items-center justify-center gap-3">
              <button onClick={() => setMicOn(!micOn)}
                className={`px-4 py-2 rounded-full text-xs font-semibold border flex items-center gap-2 transition-all ${micOn ? "bg-white text-black border-white" : "bg-white/5 text-white/60 border-white/10 hover:border-white/20"
                  }`}>
                <CgMic size={14} />
                <span>{micOn ? "Mic Enabled" : "Mic Muted"}</span>
              </button>
              <button onClick={() => setCamOn(!camOn)}
                className={`px-4 py-2 rounded-full text-xs font-semibold border flex items-center gap-2 transition-all ${camOn ? "bg-white text-black border-white" : "bg-white/5 text-white/60 border-white/10 hover:border-white/20"
                  }`}>
                <CgCamera size={14} />
                <span>{camOn ? "Video Enabled" : "Video Disabled"}</span>
              </button>
            </div>
          </div>
        </section>

        {/* ── Right sidebar – Friends + Suggested ──────────────────── */}
        <aside className="w-64 flex-shrink-0 hidden lg:flex flex-col glass-panel rounded-3xl overflow-hidden p-4 space-y-6">
          <div className="space-y-4">
            <div className="px-1">
              <div className="text-[10px] font-bold text-white/40 uppercase tracking-widest">Friends</div>
              <div className="text-[11px] text-white/50">Online friends (click to call)</div>
            </div>

            <div className="space-y-1.5 max-h-[220px] overflow-y-auto pr-1">
              {friends.length === 0 ? (
                <div className="text-center py-6 text-white/30 space-y-2">
                  <FaUserFriends className="mx-auto text-white/20" size={24} />
                  <p className="text-[10px]">No friends yet. Add some below!</p>
                </div>
              ) : (
                friends.map((f, i) => {
                  const name = typeof f === "string" ? f : f.username || "User";
                  const fInitial = name[0]?.toUpperCase() || "U";
                  const isOnline = typeof f === "object" ? f.isOnline : false;
                  return (
                    <div key={i}
                      onClick={() => startFriendChat(f)}
                      className="flex items-center gap-3 rounded-2xl p-2 hover:bg-white/5 border border-transparent hover:border-white/5 transition-all cursor-pointer group">
                      <div className="relative flex-shrink-0">
                        <div className="h-8 w-8 rounded-xl bg-white text-black flex items-center justify-center text-xs font-bold">
                          {fInitial}
                        </div>
                        {isOnline && (
                          <span className="absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full bg-emerald-400 border-2 border-[#050505]" />
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="text-xs font-bold truncate group-hover:text-white transition-colors">{name}</div>
                        <div className="text-[10px] text-white/40">
                          {isOnline ? <span className="text-emerald-400 font-medium">Online</span> : "Offline"}
                        </div>
                      </div>
                      <span className="text-white/20 group-hover:text-white text-xs transition-transform group-hover:translate-x-0.5">→</span>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Suggested Users */}
          {suggested.length > 0 && (
            <div className="space-y-4 pt-4 border-t border-white/5">
              <div className="px-1">
                <div className="text-[10px] font-bold text-white/40 uppercase tracking-widest">Discover Users</div>
              </div>
              <div className="space-y-2 max-h-[170px] overflow-y-auto pr-1 no-scrollbar">
                {suggested.map((u, i) => {
                  const uid = u._id || u.id;
                  const name = u.username || "User";
                  const isF = followingIds.has(uid?.toString());
                  return (
                    <div key={i} className="flex items-center gap-2.5 p-1.5 rounded-2xl hover:bg-white/[0.02] border border-transparent transition-all">
                      <div className="h-7 w-7 flex-shrink-0 rounded-lg bg-white/10 text-white flex items-center justify-center text-xs font-bold">
                        {name[0]?.toUpperCase()}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="text-xs font-semibold truncate text-white/90">{name}</div>
                        {u.commonCount > 0 && (
                          <div className="text-[9px] text-white/40">{u.commonCount} mutual topic{u.commonCount !== 1 ? "s" : ""}</div>
                        )}
                      </div>
                      <button onClick={() => handleFollowSuggested(uid?.toString())}
                        className={`flex-shrink-0 text-[10px] px-2.5 py-1 rounded-full border transition-all font-semibold ${isF ? "border-white/15 text-white/40 hover:border-rose-500/30 hover:text-rose-400"
                            : "border-white text-black bg-white hover:bg-transparent hover:text-white"
                          }`}>
                        {isF ? "Following" : "Follow"}
                      </button>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </aside>
      </main>

      {/* ── Beautiful Glassmorphic Bottom Navigation Bar for Mobile ── */}
      <div className="md:hidden fixed bottom-5 left-5 right-5 h-16 glass-panel rounded-2xl flex items-center justify-around z-40 px-3">
        <Link to="/dashboard" className="flex flex-col items-center gap-1 text-white text-xs">
          <FaHome size={18} />
          <span className="text-[9px] font-medium tracking-wide">Home</span>
        </Link>
        <Link to="/feed" className="flex flex-col items-center gap-1 text-white/45 hover:text-white text-xs transition-colors">
          <CgCommunity size={18} />
          <span className="text-[9px] font-medium tracking-wide">Feed</span>
        </Link>
        <Link to="/post" className="flex flex-col items-center gap-1 text-white/45 hover:text-white text-xs transition-colors">
          <IoIosAddCircle size={18} />
          <span className="text-[9px] font-medium tracking-wide">Post</span>
        </Link>
        <Link to="/chat-history" className="flex flex-col items-center gap-1 text-white/45 hover:text-white text-xs transition-colors">
          <FaHistory size={15} />
          <span className="text-[9px] font-medium tracking-wide">History</span>
        </Link>
        <Link to="/settings" className="flex flex-col items-center gap-1 text-white/45 hover:text-white text-xs transition-colors">
          <IoIosSettings size={18} />
          <span className="text-[9px] font-medium tracking-wide">Settings</span>
        </Link>
      </div>

      {/* Hidden Mobile Profile Dropdown Overlay */}
      {profileMenuOpen && (
        <div className="md:hidden fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-end" onClick={() => setProfileMenuOpen(false)}>
          <div className="w-full glass-panel rounded-t-3xl p-6 space-y-4 animate-float" style={{ animationDuration: "0s" }} onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center gap-3 pb-3 border-b border-white/5">
              <div className="h-12 w-12 rounded-xl bg-white text-black flex items-center justify-center font-bold text-lg">
                {initial}
              </div>
              <div>
                <div className="font-bold text-white text-sm">{displayName}</div>
                <div className="text-xs text-white/40">{handle}</div>
              </div>
            </div>
            <div className="space-y-1">
              <Link to="/settings" onClick={() => setProfileMenuOpen(false)} className="px-3.5 py-3 rounded-xl hover:bg-white/5 transition-colors font-medium flex items-center gap-3 text-white/80">
                <IoIosSettings size={16} /> Profile Settings
              </Link>
              <button onClick={() => { setProfileMenuOpen(false); handleLogout(); }}
                className="w-full text-left px-3.5 py-3 rounded-xl text-rose-300 hover:bg-rose-500/5 transition-colors font-medium flex items-center gap-3">
                <FaSignOutAlt size={14} /> Log Out
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
