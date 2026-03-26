import { useState, useEffect, useCallback } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../AuthContext";
import { useSocket } from "../SocketContext";
import { useToastHelpers } from "../Toast";
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
      if (result?.isFriend) toast.friend("You're now friends! 🎉");
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
    // Send a direct chat request — friend gets an Accept/Decline notification toast
    const room = sendDirectChatRequest(fid, fname);
    if (room) {
      navigate("/chat", { state: { friendId: fid, friendName: fname, directRoom: room } });
    }
  };

  const initial = user?.username?.[0]?.toUpperCase() || "U";

  return (
    <div className="h-screen flex flex-col bg-black text-white antialiased overflow-hidden">
      <header className="flex-shrink-0 border-b border-white/10 bg-black/60 backdrop-blur">
        <div className="px-4 sm:px-6 lg:px-8 py-3 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="font-semibold tracking-tight text-sm sm:text-base">Hangout &gt;</span>
            <span className="text-xs sm:text-sm text-gray-300">Feed</span>
          </div>
          <div className="flex items-center gap-2 text-xs">
            {/* Bell */}
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
            <Link to="/dashboard" className="bg-gray-800 px-4 py-1.5 rounded-full hover:bg-white hover:text-black transition">Dashboard</Link>
            <Link to="/post"      className="bg-gray-800 px-4 py-1.5 rounded-full hover:bg-white hover:text-black transition">Post</Link>
          </div>
        </div>
      </header>

      <main className="flex-1 min-h-0 px-2 sm:px-4 lg:px-6 py-4 flex gap-4 overflow-hidden">

        {/* Left sidebar */}
        <aside className="w-56 sm:w-64 flex-shrink-0 flex flex-col bg-white/5 border border-white/10 rounded-2xl overflow-hidden">
          <div className="flex-shrink-0 p-3 border-b border-white/10">
            <div className="text-xs font-semibold">My Interests</div>
          </div>
          <div className="flex-1 min-h-0 overflow-y-auto px-2 py-2 space-y-1">
            {interests.length === 0 ? (
              <div className="text-[11px] text-gray-500 px-2 py-4 text-center">
                No interests. <Link to="/dashboard" className="text-white underline">Add some</Link>
              </div>
            ) : (
              interests.map((tag, i) => (
                <div key={i} className="rounded-xl px-2.5 py-2 hover:bg-white/10 transition">
                  <div className="text-xs font-semibold text-gray-200">#{tag}</div>
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

        {/* Main feed */}
        <section className="flex-1 min-w-0 flex flex-col bg-white/5 border border-white/10 rounded-2xl overflow-hidden px-6 py-5">
          <div className="flex-shrink-0 mb-4 flex items-center justify-between">
            <div>
              <h2 className="text-base font-semibold">Community Feed</h2>
              <p className="text-xs text-gray-400">Posts from people you follow.</p>
            </div>
            <Link to="/chat"
              className="px-4 py-1.5 rounded-full bg-white text-black text-xs font-semibold hover:bg-gray-200 transition">
              Start Hangout
            </Link>
          </div>

          <div className="flex-1 min-h-0 overflow-y-auto space-y-3 pr-1">
            {loading && (
              <div className="flex items-center justify-center py-10">
                <div className="h-6 w-6 rounded-full border-2 border-white border-t-transparent animate-spin" />
              </div>
            )}

            {!loading && posts.length === 0 && (
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
                friends={friends}
                onToggleFollow={handleToggleFollow}
                onReact={handleLikePost}
                onChatFriend={startFriendChat}
              />
            ))}

            {hasMore && (
              <button onClick={loadMore} disabled={loadingMore}
                className="w-full py-2 text-xs text-gray-400 hover:text-white border border-white/10 hover:border-white/30 rounded-xl transition disabled:opacity-50">
                {loadingMore ? "Loading…" : "Load more"}
              </button>
            )}
          </div>
        </section>

        {/* Right sidebar */}
        <aside className="w-56 sm:w-64 flex-shrink-0 hidden md:flex flex-col bg-white/5 border border-white/10 rounded-2xl overflow-hidden">
          <div className="flex-shrink-0 px-3 py-3 border-b border-white/10">
            <div className="text-xs font-semibold uppercase tracking-widest">Friends</div>
            <div className="text-[11px] text-gray-400">Mutual follows</div>
          </div>
          <div className="flex-1 min-h-0 overflow-y-auto px-2 py-2 space-y-2">
            {friends.length === 0 ? (
              <div className="text-[11px] text-gray-500 px-2 py-4 text-center">No friends yet.</div>
            ) : (
              friends.map((f, i) => {
                const name     = typeof f === "string" ? f : f.username || "User";
                const fid      = typeof f === "string" ? f : f._id || f.id;
                const isOnline = typeof f === "object" ? f.isOnline : false;
                return (
                  <div key={i} className="flex items-center gap-2 px-2 py-2 rounded-xl hover:bg-white/10 transition">
                    <div className="relative flex-shrink-0">
                      <div className="h-8 w-8 rounded-full bg-white text-black flex items-center justify-center text-xs font-bold">
                        {name[0]?.toUpperCase()}
                      </div>
                      {isOnline && <span className="absolute bottom-0 right-0 h-2 w-2 rounded-full bg-green-400 border border-black" />}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-xs font-semibold truncate">{name}</div>
                      <button onClick={() => startFriendChat(f)}
                        className="text-[10px] text-gray-400 hover:text-white underline transition">
                        Chat →
                      </button>
                    </div>
                    <button onClick={() => handleToggleFollow(fid?.toString())}
                      className="flex-shrink-0 text-[10px] px-2 py-0.5 rounded-full border border-white/30 text-gray-400 hover:border-red-400 hover:text-red-400 transition">
                      Unfollow
                    </button>
                  </div>
                );
              })
            )}
          </div>

          {suggested.length > 0 && (
            <>
              <div className="flex-shrink-0 px-3 py-2 border-t border-white/10">
                <div className="text-[11px] font-semibold text-gray-400 uppercase tracking-widest">Suggested</div>
              </div>
              <div className="flex-shrink-0 px-2 pb-2 space-y-1">
                {suggested.map((u, i) => {
                  const uid  = u._id || u.id;
                  const name = u.username || "User";
                  const isF  = following.has(uid?.toString());
                  return (
                    <div key={i} className="flex items-center gap-2 px-2 py-1.5 rounded-xl hover:bg-white/5 transition">
                      <div className="h-7 w-7 flex-shrink-0 rounded-full bg-white/20 text-white flex items-center justify-center text-xs font-bold">
                        {name[0]?.toUpperCase()}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="text-xs font-semibold truncate">{name}</div>
                        {u.commonCount > 0 && (
                          <div className="text-[9px] text-gray-500">{u.commonCount} interest{u.commonCount !== 1 ? "s" : ""}</div>
                        )}
                      </div>
                      <button onClick={() => handleToggleFollow(uid?.toString())}
                        className={`flex-shrink-0 text-[10px] px-2 py-0.5 rounded-full border transition ${
                          isF ? "border-white/30 text-gray-400 hover:border-red-400 hover:text-red-400"
                              : "border-white text-white hover:bg-white hover:text-black"
                        }`}>
                        {isF ? "Unfollow" : "Follow"}
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
    <article className="rounded-2xl bg-black/70 border border-white/10 px-4 py-3">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-2 min-w-0">
          <div className="h-8 w-8 flex-shrink-0 rounded-full bg-white text-black flex items-center justify-center text-xs font-bold">
            {authorName[0]?.toUpperCase() || "U"}
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-1.5">
              <span className="text-xs font-semibold">{authorName}</span>
              {authorRank > 0 && <span className="text-[10px] text-yellow-400">★ {authorRank}</span>}
            </div>
            <div className="text-[11px] text-gray-400">{timeStr}</div>
          </div>
        </div>
        {!isMe && authorId && (
          <div className="flex items-center gap-1.5 flex-shrink-0">
            {isFriend && (
              <button onClick={() => onChatFriend({ _id: authorId, username: authorName })}
                className="text-[10px] px-2 py-0.5 rounded-full border border-green-400/50 text-green-400 hover:bg-green-400 hover:text-black transition">
                Chat
              </button>
            )}
            <button onClick={() => onToggleFollow(authorId?.toString())}
              className={`text-[10px] px-2 py-0.5 rounded-full border transition ${
                isFollowing ? "border-white/30 text-gray-400 hover:border-red-400 hover:text-red-400"
                            : "border-white text-white hover:bg-white hover:text-black"
              }`}>
              {isFollowing ? "Unfollow" : "Follow"}
            </button>
          </div>
        )}
      </div>

      <p className="mt-2 text-sm leading-relaxed">{post.content}</p>

      <div className="mt-3 flex gap-2 text-[11px]">
        <button onClick={() => onReact(post._id || post.id, "like")}
          className={`px-2.5 py-1 rounded-full border transition flex items-center gap-1 ${
            post.userLiked ? "bg-white text-black border-white" : "bg-white/5 border-white/15 hover:bg-white/10"
          }`}>
          👍 {post.likeCount ?? 0}
        </button>
        <button onClick={() => onReact(post._id || post.id, "dislike")}
          className={`px-2.5 py-1 rounded-full border transition flex items-center gap-1 ${
            post.userDisliked ? "bg-white text-black border-white" : "bg-white/5 border-white/15 hover:bg-white/10"
          }`}>
          👎 {post.dislikeCount ?? 0}
        </button>
      </div>
    </article>
  );
}
