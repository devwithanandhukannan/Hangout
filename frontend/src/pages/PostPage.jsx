import { useState, useEffect, useCallback } from "react";
import { Link } from "react-router-dom";
import { 
  getPosts, createPost, deletePost, getInterests, getProfile, 
  likePost, dislikePost, getComments, addComment, deleteComment 
} from "../api";
import { useAuth } from "../AuthContext";
import { useToastHelpers } from "../Toast";
import { 
  FaHome, FaHistory, FaStar, FaThumbsUp, FaThumbsDown, FaTrashAlt,
  FaRegThumbsUp, FaRegThumbsDown, FaRegComment, FaTimes, FaPlus 
} from "react-icons/fa";
import { CgCommunity } from "react-icons/cg";
import { IoIosAddCircle, IoIosSettings } from "react-icons/io";

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
    <div className="h-screen flex flex-col bg-[#030303] text-white antialiased overflow-hidden pb-20 md:pb-0">
      {/* Background glow elements */}
      <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] rounded-full bg-blue-500/5 blur-[120px] pointer-events-none pulse-glow-bg" />
      <div className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] rounded-full bg-rose-500/5 blur-[120px] pointer-events-none pulse-glow-bg" style={{ animationDelay: "-3s" }} />

      {/* Header */}
      <header className="flex-shrink-0 border-b border-white/5 bg-black/30 backdrop-blur-md z-30">
        <div className="px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="h-6 w-6 rounded-lg bg-white flex items-center justify-center font-black text-black text-xs tracking-wider">H</div>
            <span className="font-bold tracking-tight text-sm text-white/90">Hangout</span>
          </div>
        </div>
      </header>

      {/* Body */}
      <main className="flex-1 min-h-0 px-4 sm:px-6 py-5 flex gap-5 overflow-hidden max-w-7xl mx-auto w-full z-10">

        {/* Left Sidebar */}
        <aside className="w-60 flex-shrink-0 hidden md:flex flex-col glass-panel rounded-3xl overflow-hidden p-4 space-y-6">
          <div className="space-y-1.5">
            <div className="text-[10px] font-bold text-white/40 uppercase tracking-widest px-2.5">Workspace</div>
            <div className="space-y-0.5">
              <Link to="/dashboard"
                className="flex items-center gap-3 rounded-xl px-3 py-2.5 hover:bg-white/5 text-xs font-semibold text-white/60 hover:text-white transition-all">
                <FaHome className="text-white/50" /> Home
              </Link>
              <Link to="/feed"
                className="flex items-center gap-3 rounded-xl px-3 py-2.5 hover:bg-white/5 text-xs font-semibold text-white/60 hover:text-white transition-all">
                <CgCommunity className="text-white/50" size={15} /> Community Feed
              </Link>
              <Link to="/post"
                className="flex items-center gap-3 rounded-xl px-3 py-2.5 bg-white/5 border border-white/5 text-xs font-semibold text-white transition-all">
                <IoIosAddCircle className="text-white/80" size={16} /> Post Something
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

          <div className="space-y-3 pt-4 border-t border-white/5">
            <div className="text-[10px] font-bold text-white/40 uppercase tracking-widest px-2.5">My Topics</div>
            <div className="space-y-1 max-h-[140px] overflow-y-auto px-1 pr-1">
              {interests.length === 0 ? (
                <div className="text-[10px] text-white/30 px-2 py-2">
                  No interests. <Link to="/dashboard" className="text-white underline">Add some</Link>
                </div>
              ) : (
                interests.map((tag, i) => (
                  <div key={i} className="rounded-xl px-2.5 py-1.5 bg-white/[0.02] border border-white/5 text-xs text-white/70">
                    #{tag}
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="flex-1" />
          <div className="flex items-center justify-between border-t border-white/5 pt-4 px-1">
            <span className="text-[10px] font-semibold text-white/40 uppercase tracking-widest">Rank</span>
            <span className="text-xs font-bold text-amber-400 flex items-center gap-1">
              <FaStar size={10} /> {rankScore}
            </span>
          </div>
          <div className="flex items-center gap-3 border-t border-white/5 pt-4 px-1">
            <div className="h-9 w-9 flex-shrink-0 rounded-xl bg-white text-black flex items-center justify-center font-bold text-sm">{initial}</div>
            <div className="min-w-0">
              <div className="text-xs font-bold truncate text-white">{user?.username || "User"}</div>
              <div className="text-[10px] text-white/40 truncate">@{user?.username || "user"}</div>
            </div>
          </div>
        </aside>

        {/* Main Work Space */}
        <section className="flex-1 min-w-0 flex flex-col glass-panel rounded-3xl overflow-hidden p-6 gap-6">
          <div className="flex-shrink-0 flex flex-col border-b border-white/5 pb-4">
            <h2 className="text-base font-bold text-white/95 tracking-tight">Your Space</h2>
            <p className="text-xs text-white/50">Publish posts, share updates, and receive comments.</p>
          </div>

          {error && (
            <div className="flex-shrink-0 text-xs text-rose-400 bg-rose-500/5 border border-rose-500/20 rounded-xl px-4 py-2.5">{error}</div>
          )}

          {/* Compose Post */}
          <div className="flex-shrink-0 bg-white/[0.02] border border-white/5 rounded-2xl p-4 flex gap-3.5">
            <div className="h-9 w-9 flex-shrink-0 rounded-xl bg-white text-black flex items-center justify-center font-bold text-sm">{initial}</div>
            <div className="flex-1 min-w-0 flex flex-col gap-3">
              <textarea rows={2} placeholder="Share something with Hangout..."
                value={postText}
                onChange={(e) => setPostText(e.target.value.slice(0, 280))}
                onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); handlePost(); } }}
                className="w-full bg-transparent text-xs sm:text-sm outline-none resize-none placeholder:text-white/30 text-white/90"
              />
              <div className="flex items-center justify-between text-[10px] text-white/40 border-t border-white/[0.03] pt-3">
                <span className={postText.length > 260 ? "text-rose-400 font-bold" : ""}>{postText.length} / 280</span>
                <button onClick={handlePost} disabled={submitting || !postText.trim()}
                  className="glass-btn-primary px-4 py-2 rounded-full text-xs font-semibold disabled:opacity-50">
                  {submitting ? "Publishing..." : "Publish"}
                </button>
              </div>
            </div>
          </div>

          {/* Posts list */}
          <div className="flex-1 min-h-0 overflow-y-auto space-y-4 pr-1 no-scrollbar">
            {loading && <div className="text-center text-white/30 text-xs py-10">Loading posts...</div>}
            {!loading && posts.length === 0 && (
              <div className="text-center text-white/30 text-xs py-10">You haven't shared any posts yet. Publish something!</div>
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

        {/* Right sidebar */}
        <aside className="w-64 flex-shrink-0 hidden lg:flex flex-col glass-panel rounded-3xl overflow-hidden p-4 space-y-6">
          <div className="space-y-4">
            <div className="px-1">
              <div className="text-[10px] font-bold text-white/40 uppercase tracking-widest">Friends</div>
            </div>
            {friends.length === 0 ? (
              <div className="text-center py-6 text-white/30 text-xs">No mutual follows yet.</div>
            ) : (
              <div className="space-y-2 max-h-[350px] overflow-y-auto pr-1">
                {friends.map((f, i) => {
                  const name = typeof f === "string" ? f : f.username || "User";
                  const isOnline = typeof f === "object" ? f.isOnline : false;
                  return (
                    <div key={i} className="flex items-center gap-3 p-2 rounded-2xl bg-white/[0.01] hover:bg-white/5 border border-transparent hover:border-white/5 transition-all">
                      <div className="relative flex-shrink-0">
                        <div className="h-8 w-8 rounded-xl bg-white text-black flex items-center justify-center text-xs font-bold">
                          {name[0]?.toUpperCase()}
                        </div>
                        {isOnline && (
                          <span className="absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full bg-emerald-400 border-2 border-[#050505]" />
                        )}
                      </div>
                      <div className="min-w-0">
                        <div className="text-xs font-bold truncate text-white/95">{name}</div>
                        {isOnline ? (
                          <div className="text-[9px] text-emerald-400 font-semibold">Online</div>
                        ) : (
                          <div className="text-[9px] text-white/30">Offline</div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </aside>
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
        <Link to="/post" className="flex flex-col items-center gap-1 text-white text-xs">
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
    </div>
  );
}

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
    <article className="bg-white/[0.02] border border-white/5 rounded-2xl p-4 space-y-3 hover:border-white/10 transition-colors">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="h-8 w-8 flex-shrink-0 rounded-lg bg-white/10 text-white flex items-center justify-center text-xs font-bold">
            {authorName[0]?.toUpperCase() || "U"}
          </div>
          <div className="min-w-0">
            <div className="text-xs font-bold text-white/90 truncate">{authorName}</div>
            <div className="text-[10px] text-white/40">{timeStr}</div>
          </div>
        </div>
        <button onClick={() => onDelete(pid)}
          className="flex-shrink-0 text-white/30 hover:text-rose-400 p-1.5 rounded-lg hover:bg-rose-500/5 border border-transparent hover:border-rose-500/10 transition-all" title="Delete Post">
          <FaTrashAlt size={11} />
        </button>
      </div>

      <p className="text-xs sm:text-sm text-white/80 leading-relaxed font-light">{post.content}</p>

      {/* Actions */}
      <div className="flex gap-3 text-[10px] border-t border-white/[0.03] pt-3 items-center">
        <button onClick={() => onReact(pid, "like")}
          className={`px-3 py-1.5 rounded-full border transition-all flex items-center gap-1.5 font-semibold ${
            post.userLiked ? "bg-white text-black border-white" : "bg-white/[0.03] border-white/5 hover:bg-white/[0.08]"
          }`}>
          {post.userLiked ? <FaThumbsUp size={10} /> : <FaRegThumbsUp size={10} />}
          <span>{post.likeCount ?? 0}</span>
        </button>
        <button onClick={() => onReact(pid, "dislike")}
          className={`px-3 py-1.5 rounded-full border transition-all flex items-center gap-1.5 font-semibold ${
            post.userDisliked ? "bg-white text-black border-white" : "bg-white/[0.03] border-white/5 hover:bg-white/[0.08]"
          }`}>
          {post.userDisliked ? <FaThumbsDown size={10} /> : <FaRegThumbsDown size={10} />}
          <span>{post.dislikeCount ?? 0}</span>
        </button>
        <button onClick={loadComments}
          className="ml-auto px-3.5 py-1.5 rounded-full bg-white/[0.03] border border-white/5 hover:bg-white/[0.08] font-semibold transition-all flex items-center gap-1.5">
          <FaRegComment size={10} />
          <span>{showComments ? "Hide Comments" : "Comments"}</span>
        </button>
      </div>

      {/* Comments section */}
      {showComments && (
        <div className="mt-3 border-t border-white/5 pt-3 space-y-3">
          <form onSubmit={handleAddComment} className="flex gap-2">
            <div className="h-6 w-6 flex-shrink-0 rounded-lg bg-white/10 text-white flex items-center justify-center text-[10px] font-bold">{initial}</div>
            <input type="text" value={commentText} onChange={(e) => setCommentText(e.target.value)}
              placeholder="Write a comment..."
              className="flex-1 min-w-0 rounded-full glass-input px-3.5 py-1.5 text-[11px] outline-none" />
            <button type="submit" disabled={postingComment || !commentText.trim()}
              className="flex-shrink-0 glass-btn px-3 py-1 rounded-full text-[10px] font-bold disabled:opacity-50">
              {postingComment ? "..." : "Send"}
            </button>
          </form>

          {loadingComments && (
            <div className="flex justify-center py-2">
              <div className="h-4 w-4 rounded-full border border-white border-t-transparent animate-spin" />
            </div>
          )}

          {!loadingComments && comments.length === 0 && (
            <p className="text-[10px] text-white/30 pl-8">No comments yet.</p>
          )}

          {comments.map((c) => {
            const cid = c._id || c.id;
            const cAuthorName =
              typeof c.userId === "object" ? c.userId?.username || "Unknown"
              : typeof c.user === "object" ? c.user?.username
              : "Unknown";
            const isMyComment = (typeof c.userId === "object" ? c.userId?._id || c.userId?.id : c.userId)?.toString() === myId?.toString();
            return (
              <div key={cid} className="flex items-start gap-2.5 pl-2">
                <div className="h-6 w-6 flex-shrink-0 rounded-lg bg-white/10 text-white flex items-center justify-center text-[9px] font-bold">
                  {cAuthorName[0]?.toUpperCase() || "U"}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span className="text-[11px] font-semibold text-white/80">{cAuthorName}</span>
                    {c.createdAt && (
                      <span className="text-[9px] text-white/30">
                        · {new Date(c.createdAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] text-white/60 leading-relaxed font-light">{c.content}</p>
                </div>
                {isMyComment && (
                  <button onClick={() => handleDeleteComment(cid)}
                    className="flex-shrink-0 text-white/30 hover:text-rose-400 p-1.5 transition-colors">
                    <FaTrashAlt size={9} />
                  </button>
                )}
              </div>
            );
          })}
        </div>
      )}
    </article>
  );
}
