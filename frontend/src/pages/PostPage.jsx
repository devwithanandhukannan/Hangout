import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { getPosts, createPost, deletePost, getInterests, getProfile } from "../api";
import { useAuth } from "../AuthContext";

function parseInterests(raw) {
  if (!raw) return [];
  if (typeof raw === "string") return raw.split(",").map((s) => s.trim()).filter(Boolean);
  if (Array.isArray(raw))
    return raw.flatMap((item) => (typeof item === "string" ? item.split(",") : [item]))
              .map((s) => s.trim()).filter(Boolean);
  return [];
}

function LocalReactions() {
  const [r, setR] = useState({ heart: 0, up: 0, down: 0 });
  return (
    <div className="mt-3 flex gap-2 text-[11px]">
      {[{ k: "heart", e: "❤️" }, { k: "up", e: "👍" }, { k: "down", e: "👎" }].map(({ k, e }) => (
        <button key={k} onClick={() => setR((prev) => ({ ...prev, [k]: prev[k] + 1 }))}
          className="px-2 py-1 rounded-full bg-white/5 border border-white/15 hover:bg-white/10 transition">
          {e} {r[k]}
        </button>
      ))}
    </div>
  );
}

export default function PostPage() {
  const { user }  = useAuth();
  const [posts, setPosts]         = useState([]);
  const [postText, setPostText]   = useState("");
  const [loading, setLoading]     = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError]         = useState("");
  const [interests, setInterests] = useState([]);
  const [friends, setFriends]     = useState([]);

  useEffect(() => {
    Promise.all([getPosts(), getInterests(), getProfile()])
      .then(([postsData, intData, profileData]) => {
        setPosts(Array.isArray(postsData) ? postsData : postsData.posts || []);
        setInterests(parseInterests(intData.interests));
        const p = profileData.user || profileData;
        setFriends(p.friends || p.following || []);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  const handlePost = async () => {
    if (!postText.trim()) return;
    setSubmitting(true); setError("");
    try {
      await createPost(postText.trim());
      const data = await getPosts();
      setPosts(Array.isArray(data) ? data : data.posts || []);
      setPostText("");
    } catch (err) { setError(err.message || "Failed to post"); }
    finally { setSubmitting(false); }
  };

  const handleDelete = async (postId) => {
    try {
      await deletePost(postId);
      setPosts((prev) => prev.filter((p) => (p._id || p.id) !== postId));
    } catch (err) { setError(err.message || "Failed to delete"); }
  };

  const initial = user?.username?.[0]?.toUpperCase() || "U";

  return (
    <div className="h-screen flex flex-col bg-black text-white antialiased overflow-hidden">
      {/* Header */}
      <header className="flex-shrink-0 border-b border-white/10 bg-black/60 backdrop-blur">
        <div className="px-6 py-3 flex items-center justify-between">
          <div className="text-sm font-semibold">
            Hangout <span className="text-gray-400">› Post</span>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <Link to="/dashboard" className="px-4 py-1.5 rounded-full bg-gray-800 hover:bg-white hover:text-black transition">Dashboard</Link>
            <Link to="/feed"      className="px-4 py-1.5 rounded-full bg-gray-800 hover:bg-white hover:text-black transition">Feed</Link>
          </div>
        </div>
      </header>

      {/* Body */}
      <main className="flex-1 min-h-0 px-4 py-4 flex gap-4 overflow-hidden">

        {/* ── Left sidebar ─────────────────────────────────────────────── */}
        <aside className="w-56 sm:w-64 flex-shrink-0 flex flex-col bg-white/5 border border-white/10 rounded-2xl overflow-hidden">
          <div className="flex-shrink-0 p-3 border-b border-white/10">
            <p className="text-xs font-semibold">My Interests</p>
          </div>
          <div className="flex-1 min-h-0 overflow-y-auto px-2 py-2 space-y-1">
            {interests.length === 0 ? (
              <div className="text-[11px] text-gray-500 px-2 py-4 text-center">
                No interests.{" "}<Link to="/dashboard" className="text-white underline">Add some</Link>
              </div>
            ) : (
              interests.map((tag, i) => (
                <div key={i} className="rounded-xl px-3 py-2 hover:bg-white/10 transition">
                  <div className="text-xs font-semibold">#{tag}</div>
                </div>
              ))
            )}
          </div>
          <div className="flex-shrink-0 border-t border-white/10 p-3 flex items-center gap-2">
            <div className="h-9 w-9 flex-shrink-0 rounded-full bg-white text-black flex items-center justify-center font-semibold text-sm">{initial}</div>
            <div className="min-w-0">
              <div className="text-xs font-semibold truncate">{user?.username || "User"}</div>
              <div className="text-[11px] text-gray-400 truncate">@{user?.username || "user"}</div>
            </div>
          </div>
        </aside>

        {/* ── Main ─────────────────────────────────────────────────────── */}
        <section className="flex-1 min-w-0 flex flex-col bg-white/5 border border-white/10 rounded-2xl overflow-hidden px-6 py-4">
          <div className="flex-shrink-0 mb-4">
            <h2 className="text-sm font-semibold">Your Hangout feed</h2>
            <p className="text-xs text-gray-400">Post quick thoughts and see recent chats.</p>
          </div>

          {error && (
            <div className="flex-shrink-0 text-xs text-red-400 bg-red-400/10 border border-red-400/20 rounded-xl px-3 py-2 mb-3">{error}</div>
          )}

          {/* Compose */}
          <div className="flex-shrink-0 bg-black/70 border border-white/15 rounded-2xl px-4 py-3 mb-4 flex gap-3">
            <div className="h-8 w-8 flex-shrink-0 rounded-full bg-white text-black flex items-center justify-center text-xs font-semibold">{initial}</div>
            <div className="flex-1 min-w-0 flex flex-col gap-2">
              <textarea rows={2} placeholder="Share something with Hangout…"
                value={postText}
                onChange={(e) => setPostText(e.target.value.slice(0, 280))}
                onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); handlePost(); } }}
                className="w-full bg-transparent text-sm outline-none resize-none placeholder:text-gray-500"
              />
              <div className="flex items-center justify-between text-[11px] text-gray-500">
                <span className={postText.length > 260 ? "text-red-400" : ""}>{postText.length} / 280</span>
                <button onClick={handlePost} disabled={submitting || !postText.trim()}
                  className="px-4 py-1.5 rounded-full text-xs font-semibold bg-white text-black hover:bg-gray-100 disabled:opacity-50 transition">
                  {submitting ? "Posting…" : "Post"}
                </button>
              </div>
            </div>
          </div>

          {/* Posts */}
          <div className="flex-1 min-h-0 overflow-y-auto space-y-3">
            {loading && <div className="text-center text-gray-500 text-sm py-10">Loading posts…</div>}
            {!loading && posts.length === 0 && (
              <div className="text-center text-gray-500 text-sm py-10">No posts yet. Share something!</div>
            )}
            {posts.map((post) => {
              const pid = post._id || post.id;
              const authorName =
                (typeof post.userId === "object" ? post.userId?.username : null) || user?.username || "You";
              const timeStr = post.createdAt
                ? new Date(post.createdAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "just now";
              const dateStr = post.createdAt ? new Date(post.createdAt).toLocaleDateString() : "";
              return (
                <article key={pid} className="bg-black/70 border border-white/10 rounded-2xl px-4 py-3">
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <div className="h-8 w-8 flex-shrink-0 rounded-full bg-white text-black flex items-center justify-center text-xs font-semibold">
                        {authorName[0]?.toUpperCase() || "U"}
                      </div>
                      <div className="min-w-0">
                        <div className="text-xs font-semibold truncate">{authorName}</div>
                        <div className="text-[11px] text-gray-400">@{authorName.toLowerCase()} · {dateStr} {timeStr}</div>
                      </div>
                    </div>
                    <button onClick={() => handleDelete(pid)}
                      className="flex-shrink-0 text-xs text-gray-400 hover:text-red-400 px-1 transition" title="Delete">
                      ×
                    </button>
                  </div>
                  <p className="mt-2 text-sm leading-relaxed">{post.content}</p>
                  <LocalReactions />
                </article>
              );
            })}
          </div>
        </section>

        {/* ── Right sidebar – Friends ───────────────────────────────────── */}
        <aside className="w-56 sm:w-64 flex-shrink-0 hidden md:flex flex-col bg-white/5 border border-white/10 rounded-2xl overflow-hidden">
          <div className="flex-shrink-0 p-3 border-b border-white/10">
            <p className="text-xs font-semibold uppercase tracking-widest">Friends</p>
            <p className="text-[11px] text-gray-400">Who's around</p>
          </div>
          {friends.length === 0 ? (
            <div className="flex-1 flex items-center justify-center text-[11px] text-gray-500 px-3 text-center">No friends yet</div>
          ) : (
            <div className="flex-1 min-h-0 overflow-y-auto px-2 py-2 space-y-1">
              {friends.map((f, i) => {
                const name = typeof f === "string" ? f : f.username || "User";
                return (
                  <div key={i} className="flex items-center gap-2 px-3 py-2 rounded-xl hover:bg-white/10 transition">
                    <div className="h-8 w-8 flex-shrink-0 rounded-full bg-white text-black flex items-center justify-center text-xs font-semibold">
                      {name[0]?.toUpperCase()}
                    </div>
                    <div className="text-xs font-semibold truncate">{name}</div>
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
