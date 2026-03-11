import { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import { getFeed, getInterests, getProfile, unfollowUser } from "../api";
import { useAuth } from "../AuthContext";

function parseInterests(raw) {
  if (!raw) return [];
  if (typeof raw === "string") return raw.split(",").map((s) => s.trim()).filter(Boolean);
  if (Array.isArray(raw))
    return raw.flatMap((item) => (typeof item === "string" ? item.split(",") : [item]))
              .map((s) => s.trim()).filter(Boolean);
  return [];
}

export default function FeedPage() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [posts, setPosts]         = useState([]);
  const [interests, setInterests] = useState([]);
  const [friends, setFriends]     = useState([]);
  const [following, setFollowing] = useState([]);
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState("");
  const myId = user?._id || user?.id;

  useEffect(() => {
    Promise.all([getFeed(), getInterests(), getProfile()])
      .then(([feedData, intData, profileData]) => {
        // feedData could be array OR { message: "No posts available" }
        setPosts(Array.isArray(feedData) ? feedData : []);
        setInterests(parseInterests(intData.interests));
        const p = profileData.user || profileData;
        setFriends(p.friends || []);
        const followingIds = (p.following || []).map((f) =>
          typeof f === "string" ? f : f._id || f.id
        );
        setFollowing(followingIds);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  // Toggle follow/unfollow — backend uses /unfollow as a toggle
  const handleToggleFollow = async (targetId) => {
    try {
      await unfollowUser(targetId);
      setFollowing((prev) =>
        prev.includes(targetId)
          ? prev.filter((id) => id !== targetId)
          : [...prev, targetId]
      );
    } catch (err) {
      console.error("Follow toggle error:", err);
    }
  };

  const initial = user?.username?.[0]?.toUpperCase() || "U";

  const startFriendChat = (friend) => {
    const fid   = typeof friend === "string" ? friend : friend._id || friend.id;
    const fname = typeof friend === "string" ? friend : friend.username || "Friend";
    navigate("/chat", { state: { friendId: fid, friendName: fname } });
  };

  return (
    <div className="h-screen flex flex-col bg-black text-white antialiased overflow-hidden">
      {/* Header */}
      <header className="flex-shrink-0 border-b border-white/10 bg-black/60 backdrop-blur">
        <div className="px-4 sm:px-6 lg:px-8 py-3 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="font-semibold tracking-tight text-sm sm:text-base">Hangout &gt;</span>
            <span className="text-xs sm:text-sm text-gray-300">Feed</span>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <Link to="/dashboard" className="bg-gray-800 px-4 py-1.5 rounded-full hover:bg-white hover:text-black transition">Dashboard</Link>
            <Link to="/post"      className="bg-gray-800 px-4 py-1.5 rounded-full hover:bg-white hover:text-black transition">Post</Link>
          </div>
        </div>
      </header>

      {/* Body */}
      <main className="flex-1 min-h-0 px-2 sm:px-4 lg:px-6 py-4 flex gap-4 overflow-hidden">

        {/* ── Left sidebar ────────────────────────────────────────────────── */}
        <aside className="w-56 sm:w-64 flex-shrink-0 flex flex-col bg-white/5 border border-white/10 rounded-2xl overflow-hidden">
          <div className="flex-shrink-0 p-3 border-b border-white/10">
            <div className="text-xs font-semibold mb-1">My Interests</div>
          </div>
          <div className="flex-1 min-h-0 overflow-y-auto px-2 py-2 space-y-1 text-sm">
            {interests.length === 0 ? (
              <div className="text-[11px] text-gray-500 px-2 py-4 text-center">
                No interests yet.{" "}
                <Link to="/dashboard" className="text-white underline">Add some</Link>
              </div>
            ) : (
              interests.map((tag, i) => (
                <div key={i} className="rounded-xl px-2.5 py-2 hover:bg-white/10 transition">
                  <div className="text-xs font-semibold">#{tag}</div>
                </div>
              ))
            )}
          </div>
          <div className="flex-shrink-0 border-t border-white/10 px-3 py-3 flex items-center gap-3">
            <div className="h-9 w-9 flex-shrink-0 rounded-full bg-white text-black flex items-center justify-center font-bold text-sm">{initial}</div>
            <div className="min-w-0">
              <div className="text-sm font-semibold truncate">{user?.username || "User"}</div>
              <div className="text-xs text-gray-400 truncate">@{user?.username || "user"}</div>
            </div>
          </div>
        </aside>

        {/* ── Main feed ───────────────────────────────────────────────────── */}
        <section className="flex-1 min-w-0 flex flex-col bg-white/5 border border-white/10 rounded-2xl overflow-hidden px-6 py-5">
          <div className="flex-shrink-0 mb-4">
            <h2 className="text-base font-semibold">Community Feed</h2>
            <p className="text-xs text-gray-400">Posts from people you follow.</p>
          </div>

          <div className="flex-1 min-h-0 overflow-y-auto space-y-3 pr-1">
            {loading && (
              <div className="flex items-center justify-center py-10">
                <div className="h-6 w-6 rounded-full border-2 border-white border-t-transparent animate-spin" />
              </div>
            )}
            {error && (
              <div className="text-center text-red-400 text-sm py-4">{error}</div>
            )}
            {!loading && !error && posts.length === 0 && (
              <div className="flex flex-col items-center justify-center h-full gap-4 text-gray-500 text-sm text-center">
                <span className="text-4xl">📰</span>
                <p>No posts yet.</p>
                <p className="text-xs text-gray-600 max-w-xs">
                  Follow people to see their posts, or{" "}
                  <Link to="/chat" className="text-white underline">start a Hangout</Link>{" "}
                  to meet someone new.
                </p>
              </div>
            )}
            {posts.map((post) => (
              <PostCard
                key={post._id || post.id}
                post={post}
                myId={myId}
                following={following}
                onToggleFollow={handleToggleFollow}
                onChatFriend={startFriendChat}
                friends={friends}
              />
            ))}
          </div>
        </section>

        {/* ── Right sidebar – Friends ──────────────────────────────────────── */}
        <aside className="w-56 sm:w-64 flex-shrink-0 hidden md:flex flex-col bg-white/5 border border-white/10 rounded-2xl overflow-hidden">
          <div className="flex-shrink-0 px-3 py-3 border-b border-white/10">
            <div className="text-xs font-semibold uppercase tracking-widest">Friends</div>
            <div className="text-[11px] text-gray-400">Mutual follows</div>
          </div>
          {friends.length === 0 ? (
            <div className="flex-1 flex items-center justify-center text-[11px] text-gray-500 px-3 text-center">
              No friends yet. Follow people back!
            </div>
          ) : (
            <div className="flex-1 min-h-0 overflow-y-auto px-2 py-2 space-y-2">
              {friends.map((f, i) => {
                const name = typeof f === "string" ? f : f.username || "User";
                const initial = name[0]?.toUpperCase() || "U";
                const id = typeof f === "string" ? f : f._id || f.id;
                const isFollowing = following.includes(id);
                return (
                  <div key={i} className="flex items-center gap-2 px-2 py-2 rounded-xl hover:bg-white/10 transition">
                    <div className="h-8 w-8 flex-shrink-0 rounded-full bg-white text-black flex items-center justify-center text-xs font-bold">
                      {initial}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-xs font-semibold truncate">{name}</div>
                      <button
                        onClick={() => startFriendChat(f)}
                        className="text-[10px] text-gray-400 hover:text-white underline transition">
                        Chat →
                      </button>
                    </div>
                    <button onClick={() => handleToggleFollow(id)}
                      className={`flex-shrink-0 text-[10px] px-2 py-0.5 rounded-full border transition ${
                        isFollowing
                          ? "border-white/30 text-gray-400 hover:border-red-400 hover:text-red-400"
                          : "border-white text-white hover:bg-white hover:text-black"
                      }`}>
                      {isFollowing ? "Unfollow" : "Follow"}
                    </button>
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

function PostCard({ post, myId, following, onToggleFollow, onChatFriend, friends }) {
  const [reactions, setReactions] = useState({ heart: 0, up: 0, down: 0 });

  const authorObj  = post.userId;
  const authorName = (typeof authorObj === "object" ? authorObj?.username : null) || "Unknown";
  const authorId   = typeof authorObj === "object"
    ? authorObj?._id || authorObj?.id
    : authorObj;
  const isMe        = authorId?.toString() === myId?.toString();
  const isFollowing = following?.includes(authorId?.toString());
  const isFriend    = friends?.some((f) => {
    const fid = typeof f === "string" ? f : f._id || f.id;
    return fid?.toString() === authorId?.toString();
  });

  const timeStr = post.createdAt
    ? new Date(post.createdAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    : "";
  const dateStr = post.createdAt
    ? new Date(post.createdAt).toLocaleDateString()
    : "";

  const authorInitial = authorName[0]?.toUpperCase() || "U";

  return (
    <article className="rounded-2xl bg-black/70 border border-white/10 px-4 py-3">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-2 min-w-0">
          <div className="h-8 w-8 flex-shrink-0 rounded-full bg-white text-black flex items-center justify-center text-xs font-bold">
            {authorInitial}
          </div>
          <div className="min-w-0">
            <div className="text-xs font-semibold truncate">{authorName}</div>
            <div className="text-[11px] text-gray-400">
              @{authorName.toLowerCase()} · {dateStr} {timeStr}
            </div>
          </div>
        </div>
        {!isMe && authorId && (
          <div className="flex items-center gap-1.5 flex-shrink-0">
            {isFriend && (
              <button
                onClick={() => onChatFriend({ _id: authorId, username: authorName })}
                className="text-[10px] px-2 py-0.5 rounded-full border border-green-400/50 text-green-400 hover:bg-green-400 hover:text-black transition">
                Chat
              </button>
            )}
            <button onClick={() => onToggleFollow(authorId?.toString())}
              className={`text-[10px] px-2 py-0.5 rounded-full border transition ${
                isFollowing
                  ? "border-white/30 text-gray-400 hover:border-red-400 hover:text-red-400"
                  : "border-white text-white hover:bg-white hover:text-black"
              }`}>
              {isFollowing ? "Unfollow" : "Follow"}
            </button>
          </div>
        )}
      </div>
      <p className="mt-2 text-sm leading-relaxed">{post.content}</p>
      <div className="mt-3 flex gap-2 text-[11px]">
        {[{ k: "heart", e: "💖" }, { k: "up", e: "👍" }, { k: "down", e: "👎" }].map(({ k, e }) => (
          <button key={k}
            onClick={() => setReactions((prev) => ({ ...prev, [k]: prev[k] + 1 }))}
            className="px-2 py-1 rounded-full bg-white/5 border border-white/15 hover:bg-white/10 transition">
            {e} {reactions[k]}
          </button>
        ))}
      </div>
    </article>
  );
}
