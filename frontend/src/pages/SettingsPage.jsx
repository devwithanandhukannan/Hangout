import { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import { getProfile, updateProfile, getInterests, setInterests as apiSetInterests } from "../api";
import { useAuth } from "../AuthContext";

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
  const navigate = useNavigate();

  const [profile, setProfile]             = useState(null);
  const [username, setUsername]           = useState("");
  const [email, setEmail]                 = useState("");
  const [password, setPassword]           = useState("");
  const [interests, setInterests]         = useState([]);
  const [interestInput, setInterestInput] = useState("");
  const [loading, setLoading]             = useState(true);
  const [saving, setSaving]               = useState(false);
  const [status, setStatus]               = useState({ type: "", msg: "" });

  useEffect(() => {
    Promise.all([getProfile(), getInterests()])
      .then(([profileData, intData]) => {
        const p = profileData.user || profileData;
        setProfile(p);
        setUsername(p.username || "");
        setEmail(p.email || "");
        setInterests(parseInterests(intData.interests));
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
      const body = { username, email };
      if (password) body.password = password;
      await updateProfile(body);
      await refreshUser();
      setPassword("");
      showStatus("success", "Profile updated!");
    } catch (err) {
      showStatus("error", err.message || "Update failed");
    } finally {
      setSaving(false);
    }
  };

  const persistInterests = async (updated) => {
    try {
      await apiSetInterests(updated.join(", "));
      showStatus("success", "Interests saved!");
    } catch {
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

  return (
    <div className="min-h-screen bg-black text-white antialiased">
      <main className="w-full max-w-2xl mx-auto px-4 sm:px-6 py-10 sm:py-14">

        {/* Back + title */}
        <div className="flex items-center justify-between gap-3 mb-8">
          <div className="flex items-center gap-3">
            <Link to="/dashboard"
              className="h-8 w-8 flex-shrink-0 flex items-center justify-center rounded-full border border-white/30 hover:bg-white hover:text-black transition text-sm">
              ←
            </Link>
            <h1 className="text-sm font-semibold">Edit Profile</h1>
          </div>
          <button
            onClick={() => { logout(); navigate("/login"); }}
            className="text-xs text-red-400 border border-red-400/30 hover:border-red-400 px-3 py-1.5 rounded-full transition">
            Logout
          </button>
        </div>

        {/* Profile header with avatar */}
        <div className="mb-8 flex flex-wrap items-center gap-5">
          {/* Avatar — big letter */}
          <div className="h-16 w-16 rounded-full bg-white text-black flex items-center justify-center text-2xl font-bold flex-shrink-0">
            {initial}
          </div>
          <div className="flex-1 min-w-0">
            <h2 className="text-xl font-semibold truncate">{username}</h2>
            <p className="text-xs text-gray-400 mt-0.5 truncate">{email}</p>
          </div>
          {/* Stats */}
          <div className="flex gap-5 text-xs text-center">
            <div>
              <div className="font-bold text-base">{followersCount}</div>
              <div className="text-gray-400">Followers</div>
            </div>
            <div>
              <div className="font-bold text-base">{followingCount}</div>
              <div className="text-gray-400">Following</div>
            </div>
            <div>
              <div className="font-bold text-base">{friendsCount}</div>
              <div className="text-gray-400">Friends</div>
            </div>
            <div>
              <div className="font-bold text-base text-yellow-400">★ {rankScore}</div>
              <div className="text-gray-400">Rank</div>
            </div>
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

        {/* Update profile form */}
        <form onSubmit={handleUpdateProfile}
          className="mb-6 rounded-2xl bg-white/5 border border-white/10 px-5 py-5">
          <h3 className="text-xs font-semibold mb-4">Profile settings</h3>
          <div className="flex items-start gap-4">
            <div className="h-10 w-10 flex-shrink-0 rounded-full bg-white text-black flex items-center justify-center font-bold text-sm">
              {initial}
            </div>
            <div className="flex-1 min-w-0 space-y-3">
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
                <label className="block text-[11px] text-gray-300 mb-1">
                  New password <span className="text-gray-500">(leave blank to keep current)</span>
                </label>
                <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full rounded-lg bg-black border border-white/15 px-3 py-2 text-xs outline-none focus:border-white transition" />
              </div>
            </div>
            <button type="submit" disabled={saving}
              className="flex-shrink-0 mt-1 px-4 py-1.5 rounded-lg text-xs font-semibold bg-white text-black hover:bg-gray-200 disabled:opacity-50 transition">
              {saving ? "Saving…" : "Update"}
            </button>
          </div>
        </form>

        {/* Followers / Following / Friends lists */}
        {profile?.followers?.length > 0 && (
          <div className="mb-6 rounded-2xl bg-white/5 border border-white/10 px-5 py-4">
            <h3 className="text-xs font-semibold mb-3">Followers ({followersCount})</h3>
            <div className="flex flex-wrap gap-2">
              {profile.followers.map((f, i) => {
                const name = typeof f === "string" ? f : f.username || "User";
                const letter = name[0]?.toUpperCase() || "U";
                return (
                  <div key={i} className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-white/5 border border-white/10 text-[11px]">
                    <div className="h-5 w-5 rounded-full bg-white text-black flex items-center justify-center text-[10px] font-bold">{letter}</div>
                    {name}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Interests */}
        <section className="rounded-2xl bg-white/5 border border-white/10 px-5 py-5">
          <h3 className="text-xs font-semibold mb-3">Interests</h3>
          <form onSubmit={addInterest} className="flex gap-2 mb-3">
            <input placeholder="#hacking" value={interestInput}
              onChange={(e) => setInterestInput(e.target.value)}
              className="flex-1 min-w-0 rounded-xl bg-black border border-white/15 px-3 py-2 text-xs outline-none focus:border-white transition" />
            <button type="submit"
              className="flex-shrink-0 px-4 py-2 rounded-lg text-xs font-semibold bg-white text-black hover:bg-gray-200 transition">
              Add
            </button>
          </form>
          <div className="flex flex-wrap gap-2 text-[11px]">
            {interests.length === 0 && (
              <span className="text-gray-500">No interests yet.</span>
            )}
            {interests.map((tag) => (
              <span key={tag}
                className="inline-flex items-center gap-1 px-3 py-1 rounded-full bg-white/5 border border-white/10 hover:border-white/30 transition">
                #{tag}
                <button onClick={() => removeInterest(tag)}
                  className="text-gray-400 hover:text-white transition ml-0.5">✕</button>
              </span>
            ))}
          </div>
        </section>
      </main>
    </div>
  );
}
