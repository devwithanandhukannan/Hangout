import { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import { getProfile, updateProfile, getInterests, setInterests as apiSetInterests, getNotifications, markNotificationsRead, clearNotifications, searchUsers, followToggle, getLeaderboard } from "../api";
import { useAuth } from "../AuthContext";
import { useSocket } from "../SocketContext";
import { useToastHelpers } from "../Toast";

function parseInterests(raw) {
  if (!raw) return [];
  if (typeof raw === "string") return raw.split(",").map((s) => s.trim()).filter(Boolean);
  if (Array.isArray(raw))
    return raw.flatMap((item) => (typeof item === "string" ? item.split(",") : [item]))
              .map((s) => s.trim()).filter(Boolean);
  return [];
}

export default function SettingsPage() {
  const { refreshUser, logout } = useAuth();
  const { unreadCount: socketUnread, markNotificationsRead: socketMarkRead } = useSocket();
  const toast    = useToastHelpers();
  const navigate = useNavigate();

  const [profile, setProfile]               = useState(null);
  const [username, setUsername]             = useState("");
  const [email, setEmail]                   = useState("");
  const [bio, setBio]                       = useState("");
  const [password, setPassword]             = useState("");
  const [interests, setInterests]           = useState([]);
  const [interestInput, setInterestInput]   = useState("");
  const [loading, setLoading]               = useState(true);
  const [saving, setSaving]                 = useState(false);
  const [status, setStatus]                 = useState({ type: "", msg: "" });
  const [activeTab, setActiveTab]           = useState("profile"); // profile | interests | notifications | leaderboard | search
  const [notifications, setNotifications]  = useState([]);
  const [unreadCount, setUnreadCount]       = useState(socketUnread || 0);
  const [loadingNotifs, setLoadingNotifs]   = useState(false);
  const [searchQuery, setSearchQuery]       = useState("");
  const [searchResults, setSearchResults]  = useState([]);
  const [searching, setSearching]           = useState(false);
  const [leaderboard, setLeaderboard]       = useState([]);
  const [loadingLB, setLoadingLB]           = useState(false);
  const [followingIds, setFollowingIds]     = useState(new Set());

  useEffect(() => {
    Promise.all([getProfile(), getInterests()])
      .then(([profileData, intData]) => {
        const p = profileData.user || profileData;
        setProfile(p);
        setUsername(p.username || "");
        setEmail(p.email || "");
        setBio(p.bio || "");
        setInterests(parseInterests(intData.interests));
        const followingSet = new Set(
          (p.following || []).map((f) => typeof f === "string" ? f : f._id || f.id)
        );
        setFollowingIds(followingSet);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const showStatus = (type, msg) => {
    setStatus({ type, msg });
    setTimeout(() => setStatus({ type: "", msg: "" }), 3000);
  };

  const handleUpdateProfile = async (e) => {
    e.preventDefault();
    setSaving(true);
    try {
      const body = {};
      if (username) body.username = username;
      if (email)    body.email    = email;
      if (bio !== undefined) body.bio = bio;
      if (password) body.password = password;
      await updateProfile(body);
      await refreshUser();
      setPassword("");
      toast.success("Profile updated!");
      showStatus("success", "Profile updated!");
    } catch (err) {
      const msg = err.message || "Update failed";
      toast.error(msg);
      showStatus("error", msg);
    } finally {
      setSaving(false);
    }
  };

  const persistInterests = async (updated) => {
    try {
      await apiSetInterests(updated);
      toast.success("Interests saved!");
      showStatus("success", "Interests saved!");
    } catch {
      toast.error("Failed to save interests");
      showStatus("error", "Failed to save interests");
    }
  };

  const addInterest = async (e) => {
    e.preventDefault();
    const tag = interestInput.trim().replace(/^#/, "");
    if (!tag) return;
    const updated = [...new Set([...interests, tag])];
    setInterests(updated);
    setInterestInput("");
    await persistInterests(updated);
  };

  const removeInterest = async (tag) => {
    const updated = interests.filter((t) => t !== tag);
    setInterests(updated);
    await persistInterests(updated);
  };

  const loadNotifications = async () => {
    setLoadingNotifs(true);
    try {
      const data = await getNotifications();
      setNotifications(data.notifications || []);
      setUnreadCount(data.unreadCount || 0);
    } catch {}
    finally { setLoadingNotifs(false); }
  };

  const handleMarkAllRead = async () => {
    await markNotificationsRead([]);
    socketMarkRead();
    setNotifications((prev) => prev.map((n) => ({ ...n, isRead: true })));
    setUnreadCount(0);
    toast.success("All notifications marked as read");
  };

  const handleClearAll = async () => {
    await clearNotifications();
    socketMarkRead();
    setNotifications([]);
    setUnreadCount(0);
    toast.notif("Notifications cleared");
  };

  const handleSearch = async (q) => {
    setSearchQuery(q);
    if (q.trim().length < 2) { setSearchResults([]); return; }
    setSearching(true);
    try {
      const results = await searchUsers(q.trim());
      setSearchResults(Array.isArray(results) ? results : []);
    } catch {}
    finally { setSearching(false); }
  };

  const handleFollowToggle = async (uid) => {
    try {
      const result = await followToggle(uid);
      const isNowFollowing = result?.message?.includes("Followed");
      setFollowingIds((prev) => {
        const next = new Set(prev);
        if (isNowFollowing) next.add(uid);
        else next.delete(uid);
        return next;
      });
      setSearchResults((prev) =>
        prev.map((u) => (u._id || u.id) === uid ? { ...u, isFollowing: isNowFollowing } : u)
      );
      if (result?.isFriend) toast.friend("You're now friends! 🎉");
      else if (isNowFollowing) toast.follow("Now following!");
      else toast.notif("Unfollowed");
    } catch (err) {
      toast.error(err.message || "Failed");
    }
  };

  const loadLeaderboard = async () => {
    setLoadingLB(true);
    try {
      const data = await getLeaderboard(20);
      setLeaderboard(Array.isArray(data) ? data : []);
    } catch {}
    finally { setLoadingLB(false); }
  };

  useEffect(() => {
    if (activeTab === "notifications") loadNotifications();
    if (activeTab === "leaderboard")   loadLeaderboard();
  }, [activeTab]); // eslint-disable-line

  if (loading) {
    return (
      <div className="h-screen flex items-center justify-center bg-black text-white">
        <div className="h-7 w-7 rounded-full border-2 border-white border-t-transparent animate-spin" />
      </div>
    );
  }

  const initial        = username[0]?.toUpperCase() || "U";
  const followersCount = profile?.followers?.length ?? 0;
  const followingCount = profile?.following?.length ?? 0;
  const friendsCount   = profile?.friends?.length ?? 0;
  const rankScore      = profile?.rank?.count ?? 0;
  const postCount      = profile?.postCount ?? 0;

  const tabs = [
    { id: "profile",       label: "Profile"       },
    { id: "interests",     label: "Interests"     },
    { id: "notifications", label: `Notifications${unreadCount > 0 ? ` (${unreadCount})` : ""}` },
    { id: "search",        label: "Find People"   },
    { id: "leaderboard",  label: "Leaderboard"   },
  ];

  return (
    <div className="min-h-screen bg-black text-white antialiased">
      <main className="w-full max-w-2xl mx-auto px-4 sm:px-6 py-10 sm:py-14">

        {/* Back + logout */}
        <div className="flex items-center justify-between gap-3 mb-8">
          <div className="flex items-center gap-3">
            <Link to="/dashboard"
              className="h-8 w-8 flex-shrink-0 flex items-center justify-center rounded-full border border-white/30 hover:bg-white hover:text-black transition text-sm">
              ←
            </Link>
            <h1 className="text-sm font-semibold">Settings</h1>
          </div>
          <button
            onClick={() => { logout(); navigate("/login"); }}
            className="text-xs text-red-400 border border-red-400/30 hover:border-red-400 px-3 py-1.5 rounded-full transition">
            Logout
          </button>
        </div>

        {/* Profile header */}
        <div className="mb-8 flex flex-wrap items-center gap-5 bg-white/5 border border-white/10 rounded-2xl px-5 py-5">
          <div className="h-16 w-16 rounded-full bg-white text-black flex items-center justify-center text-2xl font-bold flex-shrink-0">
            {initial}
          </div>
          <div className="flex-1 min-w-0">
            <h2 className="text-xl font-semibold truncate">{username}</h2>
            <p className="text-xs text-gray-400 mt-0.5 truncate">{email}</p>
            {bio && <p className="text-xs text-gray-300 mt-1 line-clamp-2">{bio}</p>}
          </div>
          <div className="flex flex-wrap gap-4 text-xs text-center">
            <div><div className="font-bold text-base">{followersCount}</div><div className="text-gray-400">Followers</div></div>
            <div><div className="font-bold text-base">{followingCount}</div><div className="text-gray-400">Following</div></div>
            <div><div className="font-bold text-base">{friendsCount}</div><div className="text-gray-400">Friends</div></div>
            <div><div className="font-bold text-base">{postCount}</div><div className="text-gray-400">Posts</div></div>
            <div><div className="font-bold text-base text-yellow-400">★ {rankScore}</div><div className="text-gray-400">Rank</div></div>
          </div>
        </div>

        {/* Status toast */}
        {status.msg && (
          <div className={`mb-5 text-xs rounded-xl px-3 py-2 border ${
            status.type === "success"
              ? "text-green-400 bg-green-400/10 border-green-400/20"
              : "text-red-400 bg-red-400/10 border-red-400/20"
          }`}>
            {status.msg}
          </div>
        )}

        {/* Tabs */}
        <div className="flex gap-1 mb-6 overflow-x-auto pb-1">
          {tabs.map((tab) => (
            <button key={tab.id} onClick={() => setActiveTab(tab.id)}
              className={`flex-shrink-0 px-4 py-1.5 rounded-full text-xs font-medium transition ${
                activeTab === tab.id
                  ? "bg-white text-black"
                  : "text-gray-400 hover:text-white border border-white/15 hover:border-white/30"
              }`}>
              {tab.label}
            </button>
          ))}
        </div>

        {/* ── PROFILE TAB ──────────────────────────────────────────────────── */}
        {activeTab === "profile" && (
          <form onSubmit={handleUpdateProfile} className="rounded-2xl bg-white/5 border border-white/10 px-5 py-5 space-y-4">
            <h3 className="text-xs font-semibold mb-2">Profile settings</h3>

            <div className="flex items-center gap-3 mb-2">
              <div className="h-10 w-10 flex-shrink-0 rounded-full bg-white text-black flex items-center justify-center font-bold text-sm">{initial}</div>
              <div className="text-[11px] text-gray-400">Avatar shows your first letter</div>
            </div>

            <div>
              <label className="block text-[11px] text-gray-300 mb-1">Username</label>
              <input value={username} onChange={(e) => setUsername(e.target.value)}
                className="w-full rounded-lg bg-black border border-white/15 px-3 py-2 text-xs outline-none focus:border-white transition" />
            </div>
            <div>
              <label className="block text-[11px] text-gray-300 mb-1">Email</label>
              <input type="email" value={email} onChange={(e) => setEmail(e.target.value)}
                className="w-full rounded-lg bg-black border border-white/15 px-3 py-2 text-xs outline-none focus:border-white transition" />
            </div>
            <div>
              <label className="block text-[11px] text-gray-300 mb-1">Bio</label>
              <textarea rows={2} value={bio} onChange={(e) => setBio(e.target.value)}
                placeholder="Tell people about yourself…"
                className="w-full rounded-lg bg-black border border-white/15 px-3 py-2 text-xs outline-none focus:border-white transition resize-none" />
            </div>
            <div>
              <label className="block text-[11px] text-gray-300 mb-1">
                New password <span className="text-gray-500">(leave blank to keep current — min 6 chars)</span>
              </label>
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full rounded-lg bg-black border border-white/15 px-3 py-2 text-xs outline-none focus:border-white transition" />
            </div>

            <div className="flex justify-end">
              <button type="submit" disabled={saving}
                className="px-5 py-2 rounded-lg text-xs font-semibold bg-white text-black hover:bg-gray-200 disabled:opacity-50 transition">
                {saving ? "Saving…" : "Save changes"}
              </button>
            </div>

            {/* Followers list */}
            {(profile?.followers?.length ?? 0) > 0 && (
              <div className="mt-4 pt-4 border-t border-white/10">
                <h4 className="text-xs font-semibold mb-2">Followers ({followersCount})</h4>
                <div className="flex flex-wrap gap-2">
                  {profile.followers.map((f, i) => {
                    const name = typeof f === "string" ? f : f.username || "User";
                    return (
                      <div key={i} className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-white/5 border border-white/10 text-[11px]">
                        <div className="h-5 w-5 rounded-full bg-white text-black flex items-center justify-center text-[10px] font-bold">
                          {name[0]?.toUpperCase()}
                        </div>
                        {name}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </form>
        )}

        {/* ── INTERESTS TAB ────────────────────────────────────────────────── */}
        {activeTab === "interests" && (
          <div className="rounded-2xl bg-white/5 border border-white/10 px-5 py-5">
            <h3 className="text-xs font-semibold mb-3">Interests · used for matchmaking</h3>
            <form onSubmit={addInterest} className="flex gap-2 mb-4">
              <input placeholder="#hacking" value={interestInput}
                onChange={(e) => setInterestInput(e.target.value)}
                className="flex-1 min-w-0 rounded-xl bg-black border border-white/15 px-3 py-2 text-xs outline-none focus:border-white transition" />
              <button type="submit"
                className="flex-shrink-0 px-4 py-2 rounded-lg text-xs font-semibold bg-white text-black hover:bg-gray-200 transition">
                Add
              </button>
            </form>
            <div className="flex flex-wrap gap-2 text-[11px]">
              {interests.length === 0 && <span className="text-gray-500">No interests yet.</span>}
              {interests.map((tag) => (
                <span key={tag} className="inline-flex items-center gap-1 px-3 py-1 rounded-full bg-white/5 border border-white/10 hover:border-white/30 transition">
                  #{tag}
                  <button onClick={() => removeInterest(tag)} className="text-gray-400 hover:text-white transition ml-0.5">✕</button>
                </span>
              ))}
            </div>
          </div>
        )}

        {/* ── NOTIFICATIONS TAB ────────────────────────────────────────────── */}
        {activeTab === "notifications" && (
          <div className="rounded-2xl bg-white/5 border border-white/10 overflow-hidden">
            <div className="flex items-center justify-between px-5 py-4 border-b border-white/10">
              <h3 className="text-xs font-semibold">Notifications {unreadCount > 0 && <span className="text-yellow-400">({unreadCount} unread)</span>}</h3>
              <div className="flex gap-2">
                <button onClick={handleMarkAllRead} className="text-[11px] text-gray-400 hover:text-white transition">Mark all read</button>
                <button onClick={handleClearAll} className="text-[11px] text-red-400 hover:text-red-300 transition">Clear all</button>
              </div>
            </div>
            <div className="max-h-96 overflow-y-auto divide-y divide-white/5">
              {loadingNotifs && (
                <div className="flex justify-center py-8">
                  <div className="h-5 w-5 rounded-full border-2 border-white border-t-transparent animate-spin" />
                </div>
              )}
              {!loadingNotifs && notifications.length === 0 && (
                <div className="text-center text-gray-500 text-xs py-8">No notifications yet.</div>
              )}
              {notifications.map((n) => {
                const senderName = typeof n.senderId === "object" ? n.senderId?.username || "Someone" : "Someone";
                const senderInitial = senderName[0]?.toUpperCase() || "?";
                const timeStr = n.createdAt
                  ? new Date(n.createdAt).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })
                  : "";
                return (
                  <div key={n._id} className={`flex items-start gap-3 px-5 py-3 ${!n.isRead ? "bg-white/5" : ""}`}>
                    <div className="h-8 w-8 flex-shrink-0 rounded-full bg-white text-black flex items-center justify-center text-xs font-bold">
                      {senderInitial}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-xs text-gray-200">
                        <span className="font-semibold">{senderName}</span> {n.message}
                      </p>
                      <p className="text-[10px] text-gray-500 mt-0.5">{timeStr}</p>
                    </div>
                    {!n.isRead && <div className="h-2 w-2 flex-shrink-0 rounded-full bg-white mt-1" />}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* ── SEARCH TAB ───────────────────────────────────────────────────── */}
        {activeTab === "search" && (
          <div className="rounded-2xl bg-white/5 border border-white/10 px-5 py-5">
            <h3 className="text-xs font-semibold mb-3">Find People</h3>
            <div className="relative mb-4">
              <input type="text" value={searchQuery}
                onChange={(e) => handleSearch(e.target.value)}
                placeholder="Search by username (min 2 chars)…"
                className="w-full rounded-xl bg-black border border-white/15 px-3 py-2 text-xs outline-none focus:border-white transition" />
              {searching && (
                <div className="absolute right-3 top-2.5 h-3 w-3 rounded-full border border-white border-t-transparent animate-spin" />
              )}
            </div>
            <div className="space-y-2">
              {searchResults.length === 0 && searchQuery.length >= 2 && !searching && (
                <div className="text-center text-gray-500 text-xs py-4">No users found.</div>
              )}
              {searchResults.map((u) => {
                const uid  = u._id || u.id;
                const name = u.username || "User";
                const isF  = followingIds.has(uid?.toString());
                return (
                  <div key={uid} className="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-black/40 border border-white/10">
                    <div className="h-9 w-9 flex-shrink-0 rounded-full bg-white text-black flex items-center justify-center text-sm font-bold">
                      {name[0]?.toUpperCase()}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-xs font-semibold">{name}</div>
                      <div className="flex items-center gap-2 text-[10px] text-gray-400 mt-0.5">
                        {u.isOnline && <span className="text-green-400">● Online</span>}
                        {u.rank?.count > 0 && <span>★ {u.rank.count}</span>}
                      </div>
                    </div>
                    <button onClick={() => handleFollowToggle(uid?.toString())}
                      className={`flex-shrink-0 text-[10px] px-3 py-1 rounded-full border transition ${
                        isF ? "border-white/30 text-gray-400 hover:border-red-400 hover:text-red-400"
                            : "border-white text-white hover:bg-white hover:text-black"
                      }`}>
                      {isF ? "Unfollow" : "Follow"}
                    </button>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* ── LEADERBOARD TAB ──────────────────────────────────────────────── */}
        {activeTab === "leaderboard" && (
          <div className="rounded-2xl bg-white/5 border border-white/10 overflow-hidden">
            <div className="px-5 py-4 border-b border-white/10">
              <h3 className="text-xs font-semibold">Top Ranked Users ★</h3>
              <p className="text-[11px] text-gray-400 mt-0.5">Ranked by hearts received in chats.</p>
            </div>
            <div className="divide-y divide-white/5">
              {loadingLB && (
                <div className="flex justify-center py-8">
                  <div className="h-5 w-5 rounded-full border-2 border-white border-t-transparent animate-spin" />
                </div>
              )}
              {!loadingLB && leaderboard.length === 0 && (
                <div className="text-center text-gray-500 text-xs py-8">No ranked users yet.</div>
              )}
              {leaderboard.map((u, i) => {
                const uid  = u._id || u.id;
                const name = u.username || "User";
                const medal = i === 0 ? "🥇" : i === 1 ? "🥈" : i === 2 ? "🥉" : `#${i + 1}`;
                const isF  = followingIds.has(uid?.toString());
                return (
                  <div key={uid} className="flex items-center gap-3 px-5 py-3 hover:bg-white/5 transition">
                    <span className="text-base w-8 text-center flex-shrink-0">{medal}</span>
                    <div className="h-8 w-8 flex-shrink-0 rounded-full bg-white text-black flex items-center justify-center text-xs font-bold">
                      {name[0]?.toUpperCase()}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-xs font-semibold">{name}</div>
                      {u.isOnline && <div className="text-[10px] text-green-400">Online</div>}
                    </div>
                    <span className="text-yellow-400 font-bold text-sm mr-2">★ {u.rank?.count ?? 0}</span>
                    {uid?.toString() && (
                      <button onClick={() => handleFollowToggle(uid.toString())}
                        className={`flex-shrink-0 text-[10px] px-3 py-1 rounded-full border transition ${
                          isF ? "border-white/30 text-gray-400 hover:border-red-400 hover:text-red-400"
                              : "border-white text-white hover:bg-white hover:text-black"
                        }`}>
                        {isF ? "Unfollow" : "Follow"}
                      </button>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
