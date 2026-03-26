import { useState, useEffect, useCallback } from "react";
import { Link } from "react-router-dom";
import { getPosts, createPost, deletePost, getInterests, getProfile, likePost, dislikePost, getComments, addComment, deleteComment } from "../api";
import { useAuth } from "../AuthContext";
import { useToastHelpers } from "../Toast";

function parseInterests(raw) {
  if (!raw) return [];
  if (typeof raw === "string") return raw.split(",").map((s) => s.trim()).filter(Boolean);
  if (Array.isArray(raw))
    return raw.flatMap((item) => (typeof item === "string" ? item.split(",") : [item]))
              .map((s) => s.trim()).filter(Boolean);
  return [];
}

export default function PostPage() {
  const { user } = useAuth();
  const toast    = useToastHelpers();
  const myId = user?._id || user?.id;
  const initial = user?.username?.[0]?.toUpperCase() || "U";

  const [posts, setPosts]           = useState([]);
  const [postText, setPostText]     = useState("");
  const [loading, setLoading]       = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError]           = useState("");
  const [interests, setInterests]   = useState([]);
  const [friends, setFriends]       = useState([]);
  const [rankScore, setRankScore]   = useState(0);

  useEffect(() => {
    Promise.all([getPosts(), getInterests(), getProfile()])
      .then(([postsData, intData, profileData]) => {
        setPosts(Array.isArray(postsData) ? postsData : postsData.posts || []);
        setInterests(parseInterests(intData.interests));
        setFriends(profileData.friends || []);
        setRankScore(profileData.rank?.count ?? 0);
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
      toast.success("Post published!");
    } catch (err) {
      const msg = err.message || "Failed to post";
      setError(msg);
      toast.error(msg);
    }
    finally { setSubmitting(false); }
  };

  const handleDelete = async (postId) => {
    try {
      await deletePost(postId);
      setPosts((prev) => prev.filter((p) => (p._id || p.id) !== postId));
      toast.notif("Post deleted");
    } catch (err) {
      const msg = err.message || "Failed to delete";
      setError(msg);
      toast.error(msg);
    }
  };

  const handleReact = useCallback(async (postId, reaction) => {
    try {
      const fn = reaction === "like" ? likePost : dislikePost;
      const result = await fn(postId);
      setPosts((prev) => prev.map((p) =>
        (p._id || p.id) === postId
          ? { ...p, likeCount: result.likeCount, dislikeCount: result.dislikeCount, userLiked: result.userLiked, userDisliked: result.userDisliked }
          : p
      ));
    } catch {}
  }, []);

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

        {/* ── Left sidebar ──────────────────────────────────────────────── */}
        <aside className="w-56 sm:w-64 flex-shrink-0 flex flex-col bg-white/5 border border-white/10 rounded-2xl overflow-hidden">
          <div className="flex-shrink-0 p-3 border-b border-white/10">
            <p className="text-xs font-semibold">My Interests</p>
          </div>
          <div className="flex-1 min-h-0 overflow-y-auto px-2 py-2 space-y-1">
            {interests.length === 0 ? (
              <div className="text-[11px] text-gray-500 px-2 py-4 text-center">
                No interests. <Link to="/dashboard" className="text-white underline">Add some</Link>
              </div>
            ) : (
              interests.map((tag, i) => (
                <div key={i} className="rounded-xl px-3 py-2 hover:bg-white/10 transition">
                  <div className="text-xs font-semibold">#{tag}</div>
                </div>
              ))
            )}
          </div>

          {/* Rank */}
          <div className="flex-shrink-0 border-t border-white/10 px-3 py-2 flex items-center justify-between">
            <span className="text-[11px] text-gray-400">Your rank</span>
            <span className="text-sm font-bold text-yellow-400">★ {rankScore}</span>
          </div>

          {/* Profile */}
          <div className="flex-shrink-0 border-t border-white/10 p-3 flex items-center gap-2">
            <div className="h-9 w-9 flex-shrink-0 rounded-full bg-white text-black flex items-center justify-center font-semibold text-sm">{initial}</div>
            <div className="min-w-0">
              <div className="text-xs font-semibold truncate">{user?.username || "User"}</div>
              <div className="text-[11px] text-gray-400 truncate">@{user?.username || "user"}</div>
            </div>
          </div>
        </aside>

        {/* ── Main ──────────────────────────────────────────────────────── */}
        <section className="flex-1 min-w-0 flex flex-col bg-white/5 border border-white/10 rounded-2xl overflow-hidden px-6 py-4">
          <div className="flex-shrink-0 mb-4">
            <h2 className="text-sm font-semibold">Your Posts</h2>
            <p className="text-xs text-gray-400">Share thoughts with your followers.</p>
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

          {/* Posts list */}
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
                ? new Date(post.createdAt).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })
                : "just now";

              return (
                <PostItem
                  key={pid}
                  post={post}
                  pid={pid}
                  authorName={authorName}
                  timeStr={timeStr}
                  myId={myId}
                  initial={initial}
                  onDelete={handleDelete}
                  onReact={handleReact}
                />
              );
            })}
          </div>
        </section>

        {/* ── Right sidebar – Friends ────────────────────────────────────── */}
        <aside className="w-56 sm:w-64 flex-shrink-0 hidden md:flex flex-col bg-white/5 border border-white/10 rounded-2xl overflow-hidden">
          <div className="flex-shrink-0 p-3 border-b border-white/10">
            <p className="text-xs font-semibold uppercase tracking-widest">Friends</p>
            <p className="text-[11px] text-gray-400">Mutual follows</p>
          </div>
          {friends.length === 0 ? (
            <div className="flex-1 flex items-center justify-center text-[11px] text-gray-500 px-3 text-center">No friends yet</div>
          ) : (
            <div className="flex-1 min-h-0 overflow-y-auto px-2 py-2 space-y-1">
              {friends.map((f, i) => {
                const name = typeof f === "string" ? f : f.username || "User";
                const isOnline = typeof f === "object" ? f.isOnline : false;
                return (
                  <div key={i} className="flex items-center gap-2 px-3 py-2 rounded-xl hover:bg-white/10 transition">
                    <div className="relative flex-shrink-0">
                      <div className="h-8 w-8 rounded-full bg-white text-black flex items-center justify-center text-xs font-semibold">
                        {name[0]?.toUpperCase()}
                      </div>
                      {isOnline && (
                        <span className="absolute bottom-0 right-0 h-2 w-2 rounded-full bg-green-400 border border-black" />
                      )}
                    </div>
                    <div className="min-w-0">
                      <div className="text-xs font-semibold truncate">{name}</div>
                      {isOnline ? (
                        <div className="text-[10px] text-green-400">Online</div>
                      ) : (
                        <div className="text-[10px] text-gray-500">Offline</div>
                      )}
                    </div>
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

// Individual post with comments toggle
function PostItem({ post, pid, authorName, timeStr, myId, initial, onDelete, onReact }) {
  const [showComments, setShowComments] = useState(false);
  const [comments, setComments]         = useState([]);
  const [commentText, setCommentText]   = useState("");
  const [loadingComments, setLoadingComments] = useState(false);
  const [postingComment, setPostingComment]   = useState(false);

  const loadComments = async () => {
    if (showComments) { setShowComments(false); return; }
    setShowComments(true);
    setLoadingComments(true);
    try {
      const data = await getComments(pid);
      setComments(Array.isArray(data) ? data : []);
    } catch {}
    finally { setLoadingComments(false); }
  };

  const handleAddComment = async (e) => {
    e.preventDefault();
    if (!commentText.trim()) return;
    setPostingComment(true);
    try {
      const result = await addComment(pid, commentText.trim());
      setComments((prev) => [result.comment, ...prev]);
      setCommentText("");
    } catch {}
    finally { setPostingComment(false); }
  };

  const handleDeleteComment = async (cid) => {
    try {
      await deleteComment(cid);
      setComments((prev) => prev.filter((c) => (c._id || c.id) !== cid));
    } catch {}
  };

  return (
    <article className="bg-black/70 border border-white/10 rounded-2xl px-4 py-3">
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <div className="h-8 w-8 flex-shrink-0 rounded-full bg-white text-black flex items-center justify-center text-xs font-semibold">
            {authorName[0]?.toUpperCase() || "U"}
          </div>
          <div className="min-w-0">
            <div className="text-xs font-semibold truncate">{authorName}</div>
            <div className="text-[11px] text-gray-400">{timeStr}</div>
          </div>
        </div>
        <button onClick={() => onDelete(pid)}
          className="flex-shrink-0 text-xs text-gray-400 hover:text-red-400 px-1 transition" title="Delete">
          ×
        </button>
      </div>

      <p className="mt-2 text-sm leading-relaxed">{post.content}</p>

      {/* Reactions */}
      <div className="mt-3 flex gap-2 text-[11px] items-center">
        <button onClick={() => onReact(pid, "like")}
          className={`px-2.5 py-1 rounded-full border transition flex items-center gap-1 ${
            post.userLiked ? "bg-white text-black border-white" : "bg-white/5 border-white/15 hover:bg-white/10"
          }`}>
          👍 {post.likeCount ?? 0}
        </button>
        <button onClick={() => onReact(pid, "dislike")}
          className={`px-2.5 py-1 rounded-full border transition flex items-center gap-1 ${
            post.userDisliked ? "bg-white text-black border-white" : "bg-white/5 border-white/15 hover:bg-white/10"
          }`}>
          👎 {post.dislikeCount ?? 0}
        </button>
        <button onClick={loadComments}
          className="ml-auto px-2.5 py-1 rounded-full bg-white/5 border border-white/15 hover:bg-white/10 transition">
          💬 {showComments ? "Hide" : "Comments"}
        </button>
      </div>

      {/* Comments */}
      {showComments && (
        <div className="mt-3 border-t border-white/10 pt-3 space-y-2">
          <form onSubmit={handleAddComment} className="flex gap-2">
            <div className="h-6 w-6 flex-shrink-0 rounded-full bg-white text-black flex items-center justify-center text-[10px] font-semibold">{initial}</div>
            <input type="text" value={commentText} onChange={(e) => setCommentText(e.target.value)}
              placeholder="Write a comment…"
              className="flex-1 min-w-0 bg-black/40 border border-white/10 rounded-full px-3 py-1 text-xs outline-none focus:border-white/30" />
            <button type="submit" disabled={postingComment || !commentText.trim()}
              className="flex-shrink-0 px-3 py-1 rounded-full bg-white text-black text-[10px] font-semibold disabled:opacity-50 hover:bg-gray-200 transition">
              {postingComment ? "…" : "Post"}
            </button>
          </form>

          {loadingComments && (
            <div className="flex justify-center py-2">
              <div className="h-4 w-4 rounded-full border-2 border-white border-t-transparent animate-spin" />
            </div>
          )}

          {!loadingComments && comments.length === 0 && (
            <p className="text-[11px] text-gray-500 pl-8">No comments yet.</p>
          )}

          {comments.map((c) => {
            const cid = c._id || c.id;
            const cAuthorName =
              typeof c.userId === "object" ? c.userId?.username || "Unknown"
              : typeof c.user === "object" ? c.user?.username
              : "Unknown";
            const isMyComment = (typeof c.userId === "object" ? c.userId?._id || c.userId?.id : c.userId)?.toString() === myId?.toString();
            return (
              <div key={cid} className="flex items-start gap-2 pl-2">
                <div className="h-6 w-6 flex-shrink-0 rounded-full bg-white/20 text-white flex items-center justify-center text-[10px] font-semibold">
                  {cAuthorName[0]?.toUpperCase() || "U"}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-1 flex-wrap">
                    <span className="text-[11px] font-semibold">{cAuthorName}</span>
                    {c.createdAt && (
                      <span className="text-[10px] text-gray-500">
                        · {new Date(c.createdAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] text-gray-200 leading-relaxed">{c.content}</p>
                </div>
                {isMyComment && (
                  <button onClick={() => handleDeleteComment(cid)}
                    className="flex-shrink-0 text-[10px] text-gray-500 hover:text-red-400 transition">×</button>
                )}
              </div>
            );
          })}
        </div>
      )}
    </article>
  );
}
