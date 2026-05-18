import { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
    getProfile,
    updateProfile,
    getInterests,
    setInterests as apiSetInterests,
    getNotifications,
    markNotificationsRead,
    clearNotifications,
    searchUsers,
    followToggle,
    getLeaderboard
} from "../api";
import { useAuth } from "../AuthContext";
import { useSocket } from "../SocketContext";
import { useToastHelpers } from "../Toast";
import { 
  FaHome, FaHistory, FaStar, FaTrashAlt, FaBell, 
  FaSearch, FaTrophy, FaCamera, FaSignOutAlt, FaTimes, FaPlus 
} from "react-icons/fa";
import { CgCommunity } from "react-icons/cg";
import { IoIosAddCircle, IoIosSettings } from "react-icons/io";

function parseInterests(raw) {
    if (!raw) return [];
    if (typeof raw === "string")
        return raw
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean);
    if (Array.isArray(raw))
        return raw
            .flatMap((item) =>
                typeof item === "string" ? item.split(",") : [item]
            )
            .map((s) => s.trim())
            .filter(Boolean);
    return [];
}

function Avatar({ src, name, size = "h-16 w-16", textSize = "text-2xl" }) {
    const initial = name?.[0]?.toUpperCase() || "U";
    if (src) {
        return (
            <img
                src={src}
                alt={name}
                className={`${size} rounded-xl object-cover flex-shrink-0 border border-white/10`}
            />
        );
    }
    return (
        <div
            className={`${size} rounded-xl bg-white text-black
                flex items-center justify-center ${textSize}
                font-bold flex-shrink-0`}
        >
            {initial}
        </div>
    );
}

export default function SettingsPage() {
    const { refreshUser, logout } = useAuth();
    const {
        unreadCount: socketUnread,
        markNotificationsRead: socketMarkRead
    } = useSocket();
    const toast = useToastHelpers();
    const navigate = useNavigate();

    const [profile, setProfile] = useState(null);
    const [username, setUsername] = useState("");
    const [email, setEmail] = useState("");
    const [bio, setBio] = useState("");
    const [password, setPassword] = useState("");
    const [selectedFile, setSelectedFile] = useState(null);
    const [previewUrl, setPreviewUrl] = useState(null);
    const [interests, setInterests] = useState([]);
    const [interestInput, setInterestInput] = useState("");
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [status, setStatus] = useState({ type: "", msg: "" });
    const [activeTab, setActiveTab] = useState("profile");
    const [notifications, setNotifications] = useState([]);
    const [unreadCount, setUnreadCount] = useState(socketUnread || 0);
    const [loadingNotifs, setLoadingNotifs] = useState(false);
    const [searchQuery, setSearchQuery] = useState("");
    const [searchResults, setSearchResults] = useState([]);
    const [searching, setSearching] = useState(false);
    const [leaderboard, setLeaderboard] = useState([]);
    const [loadingLB, setLoadingLB] = useState(false);
    const [followingIds, setFollowingIds] = useState(new Set());

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
                    (p.following || []).map((f) =>
                        typeof f === "string" ? f : f._id || f.id
                    )
                );
                setFollowingIds(followingSet);
            })
            .catch(() => {})
            .finally(() => setLoading(false));
    }, []);

    useEffect(() => {
        if (!selectedFile) {
            setPreviewUrl(null);
            return;
        }
        const url = URL.createObjectURL(selectedFile);
        setPreviewUrl(url);
        return () => URL.revokeObjectURL(url);
    }, [selectedFile]);

    const showStatus = (type, msg) => {
        setStatus({ type, msg });
        setTimeout(() => setStatus({ type: "", msg: "" }), 3000);
    };

    const handleUpdateProfile = async (e) => {
        e.preventDefault();
        setSaving(true);
        try {
            const formData = new FormData();
            if (username) formData.append("username", username);
            if (email) formData.append("email", email);
            if (bio !== undefined) formData.append("bio", bio);
            if (password) formData.append("password", password);
            if (selectedFile) formData.append("avatar", selectedFile);

            const result = await updateProfile(formData);
            if (result.user) {
                setProfile(result.user);
            }
            await refreshUser();
            setPassword("");
            setSelectedFile(null);
            setPreviewUrl(null);
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

    const handleFileChange = (e) => {
        const file = e.target.files[0];
        if (!file) return;
        if (file.size > 2 * 1024 * 1024) {
            toast.error("Image must be under 2MB");
            return;
        }
        if (!file.type.startsWith("image/")) {
            toast.error("Only image files allowed");
            return;
        }
        setSelectedFile(file);
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
        } catch {} finally {
            setLoadingNotifs(false);
        }
    };

    const handleMarkAllRead = async () => {
        await markNotificationsRead([]);
        socketMarkRead();
        setNotifications((prev) =>
            prev.map((n) => ({ ...n, isRead: true }))
        );
        setUnreadCount(0);
        toast.success("All read!");
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
        if (q.trim().length < 2) {
            setSearchResults([]);
            return;
        }
        setSearching(true);
        try {
            const results = await searchUsers(q.trim());
            setSearchResults(Array.isArray(results) ? results : []);
        } catch {} finally {
            setSearching(false);
        }
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
                prev.map((u) =>
                    (u._id || u.id) === uid
                        ? { ...u, isFollowing: isNowFollowing }
                        : u
                )
            );
            if (result?.isFriend) toast.friend("You are now friends!");
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
        } catch {} finally {
            setLoadingLB(false);
        }
    };

    useEffect(() => {
        if (activeTab === "notifications") loadNotifications();
        if (activeTab === "leaderboard") loadLeaderboard();
    }, [activeTab]);

    if (loading) {
        return (
            <div className="h-screen flex items-center justify-center bg-[#030303] text-white">
                <div className="h-6 w-6 rounded-full border border-white border-t-transparent animate-spin" />
            </div>
        );
    }

    const usernameVal = username || "User";
    const followersCount = profile?.followers?.length ?? 0;
    const followingCount = profile?.following?.length ?? 0;
    const friendsCount = profile?.friends?.length ?? 0;
    const rankScore = profile?.rank?.count ?? 0;
    const postCount = profile?.postCount ?? 0;
    const avatarUrl = profile?.avatar || null;

    const tabs = [
        { id: "profile", label: "Profile" },
        { id: "interests", label: "Interests" },
        { id: "notifications", label: `Notifications${unreadCount > 0 ? ` (${unreadCount})` : ""}` },
        { id: "search", label: "Discover" },
        { id: "leaderboard", label: "Leaderboard" }
    ];

    return (
        <div className="min-h-screen bg-[#030303] text-white antialiased pb-20 md:pb-0">
            {/* Background glow elements */}
            <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] rounded-full bg-blue-500/5 blur-[120px] pointer-events-none pulse-glow-bg" />
            <div className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] rounded-full bg-rose-500/5 blur-[120px] pointer-events-none pulse-glow-bg" style={{ animationDelay: "-3s" }} />

            <main className="w-full max-w-2xl mx-auto px-4 sm:px-6 py-8 sm:py-12 z-10 relative">
                {/* Header back + logout */}
                <div className="flex items-center justify-between gap-3 mb-6">
                    <div className="flex items-center gap-3">
                        <Link
                            to="/dashboard"
                            className="h-9 w-9 flex-shrink-0 flex items-center
                                justify-center rounded-xl bg-white/5 border
                                border-white/10 hover:bg-white/10 transition-all text-xs"
                        >
                            ←
                        </Link>
                        <h1 className="text-sm font-bold text-white/90">Settings</h1>
                    </div>
                    <button
                        onClick={() => { logout(); navigate("/login"); }}
                        className="text-xs text-rose-300 font-semibold border
                            border-rose-500/20 hover:border-rose-500/50 hover:bg-rose-500/5
                            px-4 py-2 rounded-full transition-all flex items-center gap-1.5"
                    >
                        <FaSignOutAlt size={11} />
                        Logout
                    </button>
                </div>

                {/* Profile Overview Card */}
                <div className="mb-6 flex flex-col sm:flex-row sm:items-center gap-5 glass-panel rounded-3xl p-5 border border-white/5">
                    <Avatar
                        src={avatarUrl}
                        name={usernameVal}
                        size="h-16 w-16"
                        textSize="text-2xl"
                    />
                    <div className="flex-1 min-w-0">
                        <h2 className="text-lg font-bold text-white leading-tight truncate">{usernameVal}</h2>
                        <p className="text-xs text-white/40 mt-0.5 truncate">{email}</p>
                        {bio && (
                            <p className="text-xs text-white/60 mt-2 font-light leading-relaxed max-w-sm line-clamp-2">
                                {bio}
                            </p>
                        )}
                    </div>
                    <div className="flex flex-wrap gap-4 text-xs pt-3 sm:pt-0">
                        <div className="text-center">
                            <div className="font-bold text-sm text-white/90">{followersCount}</div>
                            <div className="text-[10px] text-white/40">Followers</div>
                        </div>
                        <div className="text-center">
                            <div className="font-bold text-sm text-white/90">{followingCount}</div>
                            <div className="text-[10px] text-white/40">Following</div>
                        </div>
                        <div className="text-center">
                            <div className="font-bold text-sm text-white/90">{friendsCount}</div>
                            <div className="text-[10px] text-white/40">Friends</div>
                        </div>
                        <div className="text-center">
                            <div className="font-bold text-sm text-white/90">{postCount}</div>
                            <div className="text-[10px] text-white/40">Posts</div>
                        </div>
                        <div className="text-center">
                            <div className="font-bold text-sm text-amber-400 flex items-center gap-0.5 justify-center">
                              <FaStar size={10} /> {rankScore}
                            </div>
                            <div className="text-[10px] text-white/40">Rank</div>
                        </div>
                    </div>
                </div>

                {/* Status toast */}
                {status.msg && (
                    <div
                        className={`mb-5 text-xs font-semibold rounded-xl px-4 py-2.5 text-center
                            border ${
                                status.type === "success"
                                    ? "text-emerald-400 bg-emerald-500/5 border-emerald-500/20"
                                    : "text-rose-400 bg-rose-500/5 border-rose-500/20"
                            }`}
                    >
                        {status.msg}
                    </div>
                )}

                {/* Tabs */}
                <div className="flex gap-1.5 mb-6 overflow-x-auto pb-1.5 no-scrollbar">
                    {tabs.map((tab) => (
                        <button
                            key={tab.id}
                            onClick={() => setActiveTab(tab.id)}
                            className={`flex-shrink-0 px-4 py-2
                                rounded-full text-xs font-semibold
                                transition-all ${
                                    activeTab === tab.id
                                        ? "bg-white text-black"
                                        : "text-white/50 hover:text-white border border-white/5 bg-white/[0.02] hover:border-white/15"
                                }`}
                        >
                            {tab.label}
                        </button>
                    ))}
                </div>

                {/* PROFILE TAB */}
                {activeTab === "profile" && (
                    <form
                        onSubmit={handleUpdateProfile}
                        className="rounded-3xl glass-panel p-6 space-y-4"
                    >
                        <h3 className="text-xs font-bold uppercase tracking-wider text-white/40 mb-2">Profile Settings</h3>

                        {/* Avatar Upload */}
                        <div className="space-y-1.5">
                            <label className="block text-[11px] font-semibold text-white/60">Avatar Image</label>
                            <div className="flex items-center gap-4">
                                <Avatar
                                    src={previewUrl || avatarUrl}
                                    name={usernameVal}
                                    size="h-14 w-14"
                                    textSize="text-xl"
                                />
                                <div className="flex-1">
                                    <input
                                        type="file"
                                        accept="image/*"
                                        onChange={handleFileChange}
                                        className="hidden"
                                        id="avatar-input"
                                    />
                                    <label
                                        htmlFor="avatar-input"
                                        className="inline-block px-4 py-2
                                            rounded-xl text-[11px] font-semibold border
                                            border-white/10 hover:border-white/30 hover:bg-white/5
                                            cursor-pointer transition-all"
                                    >
                                        Change Avatar
                                    </label>
                                    {selectedFile && (
                                        <span className="ml-3 text-[10px] text-emerald-400 font-medium">
                                            {selectedFile.name}
                                        </span>
                                    )}
                                    <p className="text-[10px] text-white/30 mt-1">Image size under 2MB · JPG, PNG, GIF</p>
                                </div>
                                {selectedFile && (
                                    <button
                                        type="button"
                                        onClick={() => { setSelectedFile(null); setPreviewUrl(null); }}
                                        className="text-[10px] text-rose-400 hover:text-rose-300 font-bold"
                                    >
                                        ✕
                                    </button>
                                )}
                            </div>
                        </div>

                        <div className="space-y-1.5">
                            <label className="block text-[11px] font-semibold text-white/60">Username</label>
                            <input
                                value={username}
                                onChange={(e) => setUsername(e.target.value)}
                                className="w-full rounded-xl glass-input px-4 py-3 text-xs outline-none focus:border-white"
                            />
                        </div>

                        <div className="space-y-1.5">
                            <label className="block text-[11px] font-semibold text-white/60">Email</label>
                            <input
                                type="email"
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                                className="w-full rounded-xl glass-input px-4 py-3 text-xs outline-none focus:border-white"
                            />
                        </div>

                        <div className="space-y-1.5">
                            <label className="block text-[11px] font-semibold text-white/60">Bio</label>
                            <textarea
                                rows={2}
                                value={bio}
                                onChange={(e) => setBio(e.target.value)}
                                placeholder="Write a short summary about yourself..."
                                className="w-full rounded-xl glass-input px-4 py-3 text-xs outline-none focus:border-white resize-none"
                            />
                        </div>

                        <div className="space-y-1.5">
                            <label className="block text-[11px] font-semibold text-white/60">
                                New Password <span className="text-white/30 font-normal">(leave blank to keep current)</span>
                            </label>
                            <input
                                type="password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                placeholder="••••••••"
                                className="w-full rounded-xl glass-input px-4 py-3 text-xs outline-none focus:border-white"
                            />
                        </div>

                        <div className="flex justify-end pt-2">
                            <button
                                type="submit"
                                disabled={saving}
                                className="glass-btn-primary px-5 py-2.5 rounded-full text-xs font-semibold disabled:opacity-50"
                            >
                                {saving ? "Saving..." : "Save Profile"}
                            </button>
                        </div>
                    </form>
                )}

                {/* INTERESTS TAB */}
                {activeTab === "interests" && (
                    <div className="rounded-3xl glass-panel p-6 space-y-4">
                        <h3 className="text-xs font-bold uppercase tracking-wider text-white/40 mb-1">My Matchmaking Topics</h3>
                        <form
                            onSubmit={addInterest}
                            className="flex gap-2"
                        >
                            <input
                                placeholder="#gaming, #tech..."
                                value={interestInput}
                                onChange={(e) => setInterestInput(e.target.value)}
                                className="flex-1 rounded-xl glass-input px-4 py-3 text-xs outline-none focus:border-white"
                            />
                            <button
                                type="submit"
                                className="glass-btn px-5 py-3 rounded-xl text-xs font-semibold hover:border-white"
                            >
                                <FaPlus size={10} className="inline mr-1" /> Add
                            </button>
                        </form>
                        <div className="flex flex-wrap gap-2 pt-2 min-h-6">
                            {interests.length === 0 && (
                                <span className="text-xs text-white/30">No matching interests set. Add topics to connect with like-minded chat partners.</span>
                            )}
                            {interests.map((tag) => (
                                <span
                                    key={tag}
                                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-white/5 border border-white/10 text-xs text-white/80"
                                >
                                    #{tag}
                                    <button
                                        onClick={() => removeInterest(tag)}
                                        className="text-white/30 hover:text-rose-400 text-[10px]"
                                    >
                                        ✕
                                    </button>
                                </span>
                            ))}
                        </div>
                    </div>
                )}

                {/* NOTIFICATIONS TAB */}
                {activeTab === "notifications" && (
                    <div className="rounded-3xl glass-panel overflow-hidden border border-white/5">
                        <div className="flex items-center justify-between px-5 py-4 border-b border-white/5 bg-white/[0.01]">
                            <h3 className="text-xs font-bold uppercase tracking-wider text-white/40">
                                Notifications {unreadCount > 0 && <span className="text-amber-400">({unreadCount} unread)</span>}
                            </h3>
                            <div className="flex gap-3">
                                <button
                                    onClick={handleMarkAllRead}
                                    className="text-[10px] text-white/45 hover:text-white font-semibold transition-colors"
                                >
                                    Mark All Read
                                </button>
                                <button
                                    onClick={handleClearAll}
                                    className="text-[10px] text-rose-400 hover:text-rose-300 font-semibold transition-colors"
                                >
                                    Clear All
                                </button>
                            </div>
                        </div>
                        <div className="max-h-96 overflow-y-auto divide-y divide-white/5 no-scrollbar">
                            {loadingNotifs && (
                                <div className="flex justify-center py-8">
                                    <div className="h-5 w-5 rounded-full border border-white border-t-transparent animate-spin" />
                                </div>
                            )}
                            {!loadingNotifs && notifications.length === 0 && (
                                <div className="text-center text-white/30 text-xs py-10">
                                    No notifications.
                                </div>
                            )}
                            {notifications.map((n) => {
                                const senderName = typeof n.senderId === "object" ? n.senderId?.username || "Someone" : "Someone";
                                const senderAvatar = typeof n.senderId === "object" ? n.senderId?.avatar : null;
                                const timeStr = n.createdAt
                                    ? new Date(n.createdAt).toLocaleString([], {
                                          month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"
                                      })
                                    : "";

                                return (
                                    <div
                                        key={n._id}
                                        className={`flex items-start gap-3.5 px-5 py-3.5 transition-colors ${!n.isRead ? "bg-white/[0.03]" : ""}`}
                                    >
                                        <Avatar
                                            src={senderAvatar}
                                            name={senderName}
                                            size="h-8 w-8"
                                            textSize="text-xs"
                                        />
                                        <div className="flex-1 min-w-0">
                                            <p className="text-xs text-white/80 leading-normal">
                                                <span className="font-bold text-white">{senderName}</span>{" "}
                                                {n.message}
                                            </p>
                                            <p className="text-[9px] text-white/30 mt-0.5">
                                                {timeStr}
                                            </p>
                                        </div>
                                        {!n.isRead && (
                                            <div className="h-2 w-2 flex-shrink-0 rounded-full bg-white mt-1.5" />
                                        )}
                                    </div>
                                );
                            })}
                        </div>
                    </div>
                )}

                {/* SEARCH TAB */}
                {activeTab === "search" && (
                    <div className="rounded-3xl glass-panel p-6 space-y-4">
                        <h3 className="text-xs font-bold uppercase tracking-wider text-white/40">Find People</h3>
                        <div className="relative">
                            <FaSearch className="absolute left-3.5 top-1/2 -translate-y-1/2 text-white/20 text-xs" />
                            <input
                                type="text"
                                value={searchQuery}
                                onChange={(e) => handleSearch(e.target.value)}
                                placeholder="Search by username..."
                                className="w-full rounded-xl glass-input pl-9 pr-4 py-3 text-xs outline-none focus:border-white"
                            />
                            {searching && (
                                <div className="absolute right-3.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 rounded-full border border-white border-t-transparent animate-spin" />
                            )}
                        </div>
                        <div className="space-y-2.5 max-h-[300px] overflow-y-auto pr-1 no-scrollbar">
                            {searchResults.length === 0 && searchQuery.length >= 2 && !searching && (
                                <div className="text-center text-white/30 text-xs py-4">No matching users found.</div>
                            )}
                            {searchResults.map((u) => {
                                const uid = u._id || u.id;
                                const name = u.username || "User";
                                const isF = followingIds.has(uid?.toString());
                                return (
                                    <div
                                        key={uid}
                                        className="flex items-center gap-3 p-2.5 rounded-2xl bg-white/[0.01] border border-white/5 hover:border-white/10 transition-all"
                                    >
                                        <Avatar
                                            src={u.avatar}
                                            name={name}
                                            size="h-9 w-9"
                                            textSize="text-sm"
                                        />
                                        <div className="flex-1 min-w-0">
                                            <div className="text-xs font-bold text-white/90 leading-tight">{name}</div>
                                            <div className="flex items-center gap-2 text-[9px] text-white/45 mt-0.5">
                                                {u.isOnline && <span className="text-emerald-400 font-semibold">● Online</span>}
                                                {u.rank?.count > 0 && <span className="flex items-center gap-0.5"><FaStar size={8} className="text-amber-400" /> {u.rank.count}</span>}
                                            </div>
                                        </div>
                                        <button
                                            onClick={() => handleFollowToggle(uid?.toString())}
                                            className={`flex-shrink-0 text-[10px] px-3 py-1.5 rounded-full border transition-all font-semibold ${
                                                isF
                                                    ? "border-white/15 text-white/40 hover:border-rose-500/30 hover:text-rose-400"
                                                    : "border-white text-black bg-white hover:bg-transparent hover:text-white"
                                            }`}
                                        >
                                            {isF ? "Following" : "Follow"}
                                        </button>
                                    </div>
                                );
                            })}
                        </div>
                    </div>
                )}

                {/* LEADERBOARD TAB */}
                {activeTab === "leaderboard" && (
                    <div className="rounded-3xl glass-panel overflow-hidden border border-white/5">
                        <div className="px-5 py-4 border-b border-white/5 bg-white/[0.01]">
                            <h3 className="text-xs font-bold uppercase tracking-wider text-white/40 flex items-center gap-1.5">
                                <FaTrophy className="text-amber-400" /> Top Ranked Users
                            </h3>
                        </div>
                        <div className="divide-y divide-white/5 max-h-96 overflow-y-auto no-scrollbar">
                            {loadingLB && (
                                <div className="flex justify-center py-8">
                                    <div className="h-5 w-5 rounded-full border border-white border-t-transparent animate-spin" />
                                </div>
                            )}
                            {!loadingLB && leaderboard.length === 0 && (
                                <div className="text-center text-white/30 text-xs py-8">No leaderboard data found.</div>
                            )}
                            {leaderboard.map((u, i) => {
                                const uid = u._id || u.id;
                                const name = u.username || "User";
                                const isF = followingIds.has(uid?.toString());
                                return (
                                    <div
                                        key={uid}
                                        className="flex items-center gap-3 px-5 py-3.5 hover:bg-white/[0.02] transition-colors"
                                    >
                                        <span className="text-xs font-bold text-white/30 w-6 text-center flex-shrink-0">
                                            #{i + 1}
                                        </span>
                                        <Avatar
                                            src={u.avatar}
                                            name={name}
                                            size="h-8 w-8"
                                            textSize="text-xs"
                                        />
                                        <div className="flex-1 min-w-0">
                                            <div className="text-xs font-bold text-white/95 truncate leading-tight">{name}</div>
                                            {u.isOnline && (
                                                <div className="text-[9px] text-emerald-400 font-semibold mt-0.5">Online</div>
                                            )}
                                        </div>
                                        <span className="text-amber-400 font-bold text-xs mr-3 flex items-center gap-0.5">
                                            <FaStar size={10} /> {u.rank?.count ?? 0}
                                        </span>
                                        <button
                                            onClick={() => handleFollowToggle(uid.toString())}
                                            className={`flex-shrink-0 text-[10px] px-3 py-1.5 rounded-full border transition-all font-semibold ${
                                                isF
                                                    ? "border-white/15 text-white/40 hover:border-rose-500/30 hover:text-rose-400"
                                                    : "border-white text-black bg-white hover:bg-transparent hover:text-white"
                                            }`}
                                        >
                                            {isF ? "Following" : "Follow"}
                                        </button>
                                    </div>
                                );
                            })}
                        </div>
                    </div>
                )}
            </main>

            {/* Glassmorphic Mobile Bottom Nav */}
            <div className="md:hidden fixed bottom-5 left-5 right-5 h-16 glass-panel rounded-2xl flex items-center justify-around z-40 px-3">
                <Link to="/dashboard" className="flex flex-col items-center gap-1 text-white/45 hover:text-white text-xs transition-colors">
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
                <Link to="/settings" className="flex flex-col items-center gap-1 text-white text-xs">
                    <IoIosSettings size={18} />
                    <span className="text-[9px] font-medium tracking-wide">Settings</span>
                </Link>
            </div>
        </div>
    );
}