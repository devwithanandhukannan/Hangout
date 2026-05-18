import { useState, useEffect, useCallback } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../AuthContext";
import { useSocket } from "../SocketContext";
import { useToastHelpers } from "../Toast";
import { 
  FaBell, FaHistory, FaUserFriends, FaHome, FaStar, FaPlus, 
  FaThumbsUp, FaThumbsDown, FaRegThumbsUp, FaRegThumbsDown, FaRegNewspaper, FaChevronRight 
} from "react-icons/fa";
import { CgCommunity } from "react-icons/cg";
import { IoIosAddCircle, IoIosSettings } from "react-icons/io";
import {
  getFeed, getInterests, getProfile,
  followToggle, likePost, dislikePost, getSuggestedUsers,
} from "../api";

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
  const { unreadCount, markNotificationsRead, sendDirectChatRequest } = useSocket();
  const toast    = useToastHelpers();
  const navigate = useNavigate();
  const myId     = user?._id || user?.id;

  const [posts, setPosts]         = useState([]);
  const [interests, setInterests] = useState([]);
  const [friends, setFriends]     = useState([]);
  const [following, setFollowing] = useState(new Set());
  const [suggested, setSuggested] = useState([]);
  const [loading, setLoading]     = useState(true);
  const [page, setPage]           = useState(1);
  const [hasMore, setHasMore]     = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);

  useEffect(() => {
    Promise.all([getFeed(1, 20), getInterests(), getProfile(), getSuggestedUsers()])
      .then(([feedData, intData, profileData, sugg]) => {
        const postsArr = feedData?.posts || (Array.isArray(feedData) ? feedData : []);
        setPosts(postsArr);
        setHasMore(feedData?.hasMore || false);
        setInterests(parseInterests(intData.interests));
        setFriends(profileData.friends || []);
        const followingIds = new Set(
          (profileData.following || []).map((f) => typeof f === "string" ? f : f._id || f.id)
        );
        setFollowing(followingIds);
        setSuggested(Array.isArray(sugg) ? sugg.slice(0, 5) : []);
      })
      .catch((err) => toast.error(err.message))
      .finally(() => setLoading(false));
  }, []); // eslint-disable-line

  const loadMore = async () => {
    setLoadingMore(true);
    try {
      const next = page + 1;
      const data = await getFeed(next, 20);
      const more = data?.posts || [];
      setPosts((prev) => [...prev, ...more]);
      setHasMore(data?.hasMore || false);
      setPage(next);
    } catch { }
    finally { setLoadingMore(false); }
  };

  const handleToggleFollow = useCallback(async (targetId) => {
    try {
      const result = await followToggle(targetId);
      const isNowFollowing = result?.message?.includes("Followed");
      setFollowing((prev) => {
        const next = new Set(prev);
        if (isNowFollowing) next.add(targetId);
        else next.delete(targetId);
        return next;
      });
      if (result?.isFriend) toast.friend("You are now friends!");
      else if (isNowFollowing) toast.follow("Following!");
      else toast.notif("Unfollowed");
    } catch (err) {
      toast.error(err.message || "Failed");
    }
  }, []); // eslint-disable-line

  const handleLikePost = useCallback(async (postId, reaction) => {
    try {
      const fn = reaction === "like" ? likePost : dislikePost;
      const result = await fn(postId);
      setPosts((prev) => prev.map((p) =>
        (p._id || p.id) === postId
          ? { ...p, likeCount: result.likeCount, dislikeCount: result.dislikeCount, userLiked: result.userLiked, userDisliked: result.userDisliked }
          : p
      ));
    } catch { }
  }, []);

  const startFriendChat = (friend) => {
    const fid   = typeof friend === "string" ? friend : friend._id || friend.id;
    const fname = typeof friend === "string" ? friend : friend.username || "Friend";
    const room = sendDirectChatRequest(fid, fname);
    if (room) {
      navigate("/chat", { state: { friendId: fid, friendName: fname, directRoom: room } });
    }
  };

  const initial = user?.username?.[0]?.toUpperCase() || "U";

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
          <div className="flex items-center gap-4">
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
                className="flex items-center gap-3 rounded-xl px-3 py-2.5 bg-white/5 border border-white/5 text-xs font-semibold text-white transition-all">
                <CgCommunity className="text-white/80" size={15} /> Community Feed
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
          <div className="flex items-center gap-3 border-t border-white/5 pt-4 px-1">
            <div className="h-9 w-9 flex-shrink-0 rounded-xl bg-white text-black flex items-center justify-center font-bold text-sm">{initial}</div>
            <div className="min-w-0">
              <div className="text-xs font-bold truncate text-white">{user?.username || "User"}</div>
              <div className="text-[10px] text-white/40 truncate">@{user?.username || "user"}</div>
            </div>
          </div>
        </aside>

        {/* Main Feed Workspace */}
        <section className="flex-1 min-w-0 flex flex-col glass-panel rounded-3xl overflow-hidden p-6 gap-6">
          <div className="flex-shrink-0 flex items-center justify-between gap-4 border-b border-white/5 pb-4">
            <div>
              <h2 className="text-base font-bold text-white/95 tracking-tight">Community Feed</h2>
              <p className="text-xs text-white/50">Discover posts and ideas from other users.</p>
            </div>
            <Link to="/chat"
              className="glass-btn-primary px-4 py-2 rounded-full text-xs font-semibold">
              Live Chat
            </Link>
          </div>

          <div className="flex-1 min-h-0 overflow-y-auto space-y-4 pr-1 no-scrollbar">
            {loading && (
              <div className="flex items-center justify-center py-20">
                <div className="h-6 w-6 rounded-full border-2 border-white border-t-transparent animate-spin" />
              </div>
            )}

            {!loading && posts.length === 0 && (
              <div className="flex flex-col items-center justify-center py-20 gap-3 text-white/30 text-center">
                <FaRegNewspaper size={36} className="text-white/20" />
                <p className="font-semibold text-sm">No feed items</p>
                <p className="text-xs max-w-xs leading-relaxed">
                  Follow some amazing creators or <Link to="/chat" className="text-white underline font-semibold">start a chat</Link> to meet new friends.
                </p>
              </div>
            )}

            {posts.map((post) => (
              <PostCard
                key={post._id || post.id}
                post={post}
                myId={myId}
                following={following}
                friends={friends}
                onToggleFollow={handleToggleFollow}
                onReact={handleLikePost}
                onChatFriend={startFriendChat}
              />
            ))}

            {hasMore && (
              <button onClick={loadMore} disabled={loadingMore}
                className="w-full py-3 text-xs font-semibold text-white/60 hover:text-white glass-btn rounded-xl disabled:opacity-50">
                {loadingMore ? "Loading..." : "Load More Posts"}
              </button>
            )}
          </div>
        </section>

        {/* Right sidebar */}
        <aside className="w-64 flex-shrink-0 hidden lg:flex flex-col glass-panel rounded-3xl overflow-hidden p-4 space-y-6">
          <div className="space-y-4">
            <div className="px-1">
              <div className="text-[10px] font-bold text-white/40 uppercase tracking-widest">Friends</div>
            </div>
            <div className="space-y-2 max-h-[220px] overflow-y-auto pr-1">
              {friends.length === 0 ? (
                <div className="text-center py-6 text-white/30 text-xs">No mutual follows yet.</div>
              ) : (
                friends.map((f, i) => {
                  const name     = typeof f === "string" ? f : f.username || "User";
                  const fid      = typeof f === "string" ? f : f._id || f.id;
                  const isOnline = typeof f === "object" ? f.isOnline : false;
                  return (
                    <div key={i} className="flex items-center gap-3 p-2 rounded-2xl bg-white/[0.01] hover:bg-white/5 border border-transparent hover:border-white/5 transition-all">
                      <div className="relative flex-shrink-0">
                        <div className="h-8 w-8 rounded-xl bg-white text-black flex items-center justify-center text-xs font-bold">
                          {name[0]?.toUpperCase()}
                        </div>
                        {isOnline && <span className="absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full bg-emerald-400 border-2 border-[#050505]" />}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="text-xs font-bold truncate text-white/95">{name}</div>
                        <button onClick={() => startFriendChat(f)}
                          className="text-[10px] text-white/40 hover:text-white underline transition-colors">
                          Call →
                        </button>
                      </div>
                      <button onClick={() => handleToggleFollow(fid?.toString())}
                        className="flex-shrink-0 text-[10px] px-2.5 py-1 rounded-full border border-white/10 text-white/40 hover:border-rose-500/30 hover:text-rose-400 font-semibold transition-colors">
                        Remove
                      </button>
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
              <div className="space-y-2 pr-1">
                {suggested.map((u, i) => {
                  const uid  = u._id || u.id;
                  const name = u.username || "User";
                  const isF  = following.has(uid?.toString());
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
                      <button onClick={() => handleToggleFollow(uid?.toString())}
                        className={`flex-shrink-0 text-[10px] px-2.5 py-1 rounded-full border transition-all font-semibold ${
                          isF ? "border-white/15 text-white/40 hover:border-rose-500/30 hover:text-rose-400"
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

      {/* Glassmorphic Mobile Bottom Nav */}
      <div className="md:hidden fixed bottom-5 left-5 right-5 h-16 glass-panel rounded-2xl flex items-center justify-around z-40 px-3">
        <Link to="/dashboard" className="flex flex-col items-center gap-1 text-white/45 hover:text-white text-xs transition-colors">
          <FaHome size={18} />
          <span className="text-[9px] font-medium tracking-wide">Home</span>
        </Link>
        <Link to="/feed" className="flex flex-col items-center gap-1 text-white text-xs">
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
    </div>
  );
}

function PostCard({ post, myId, following, friends, onToggleFollow, onReact, onChatFriend }) {
  const authorObj   = post.userId;
  const authorName  = (typeof authorObj === "object" ? authorObj?.username : null) || "Unknown";
  const authorId    = typeof authorObj === "object" ? authorObj?._id || authorObj?.id : authorObj;
  const authorRank  = typeof authorObj === "object" ? authorObj?.rank?.count ?? 0 : 0;
  const isMe        = authorId?.toString() === myId?.toString();
  const isFollowing = following?.has(authorId?.toString());
  const isFriend    = friends?.some((f) => {
    const fid = typeof f === "string" ? f : f._id || f.id;
    return fid?.toString() === authorId?.toString();
  });

  const timeStr = post.createdAt
    ? new Date(post.createdAt).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })
    : "";

  return (
    <article className="rounded-2xl bg-white/[0.02] border border-white/5 p-4 space-y-3 hover:border-white/10 transition-colors">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="h-8 w-8 flex-shrink-0 rounded-lg bg-white/10 text-white flex items-center justify-center text-xs font-bold">
            {authorName[0]?.toUpperCase() || "U"}
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-1.5">
              <span className="text-xs font-bold text-white/90">{authorName}</span>
              {authorRank > 0 && (
                <span className="text-[10px] text-amber-400 font-bold flex items-center gap-0.5">
                  <FaStar size={8} /> {authorRank}
                </span>
              )}
            </div>
            <div className="text-[10px] text-white/40">{timeStr}</div>
          </div>
        </div>
        {!isMe && authorId && (
          <div className="flex items-center gap-2 flex-shrink-0">
            {isFriend && (
              <button onClick={() => onChatFriend({ _id: authorId, username: authorName })}
                className="text-[10px] px-2.5 py-1 rounded-full border border-green-500/20 bg-green-500/5 text-green-400 hover:bg-green-500 hover:text-black font-semibold transition-all">
                Call
              </button>
            )}
            <button onClick={() => onToggleFollow(authorId?.toString())}
              className={`text-[10px] px-2.5 py-1 rounded-full border transition-all font-semibold ${
                isFollowing ? "border-white/15 text-white/40 hover:border-rose-500/30 hover:text-rose-400"
                            : "border-white text-black bg-white hover:bg-transparent hover:text-white"
              }`}>
              {isFollowing ? "Unfollow" : "Follow"}
            </button>
          </div>
        )}
      </div>

      <p className="text-xs sm:text-sm text-white/80 leading-relaxed font-light">{post.content}</p>

      <div className="flex gap-3 text-[10px] border-t border-white/[0.03] pt-3">
        <button onClick={() => onReact(post._id || post.id, "like")}
          className={`px-3 py-1.5 rounded-full border transition-all flex items-center gap-1.5 font-semibold ${
            post.userLiked ? "bg-white text-black border-white" : "bg-white/[0.03] border-white/5 hover:bg-white/[0.08]"
          }`}>
          {post.userLiked ? <FaThumbsUp size={10} /> : <FaRegThumbsUp size={10} />}
          <span>{post.likeCount ?? 0}</span>
        </button>
        <button onClick={() => onReact(post._id || post.id, "dislike")}
          className={`px-3 py-1.5 rounded-full border transition-all flex items-center gap-1.5 font-semibold ${
            post.userDisliked ? "bg-white text-black border-white" : "bg-white/[0.03] border-white/5 hover:bg-white/[0.08]"
          }`}>
          {post.userDisliked ? <FaThumbsDown size={10} /> : <FaRegThumbsDown size={10} />}
          <span>{post.dislikeCount ?? 0}</span>
        </button>
      </div>
    </article>
  );
}
