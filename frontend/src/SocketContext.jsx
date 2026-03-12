/**
 * SocketContext
 * ─────────────────────────────────────────────────────────────────────────────
 * Single Socket.IO connection shared across all pages.
 *
 * Transport order: ["polling", "websocket"]
 *   • HTTP long-polling sends the httpOnly "hangout" cookie on every request.
 *   • socketAuthMiddleware reads that cookie and attaches socket.userId.
 *   • After auth succeeds Socket.IO upgrades to WebSocket automatically.
 *   • Never put "websocket" first — the WS upgrade request does NOT re-send
 *     cookies in many browsers, so auth fails → "WebSocket closed before
 *     connection established".
 *
 * Direct-chat request flow (friend → friend):
 *  A calls sendDirectChatRequest(friendId, friendName)
 *    → socket.emit("directChatRequest", { toId, room })
 *    → backend forwards to B's socket
 *  B's SocketContext receives "directChatRequest"
 *    → shows an ACTION toast with [✓ Accept] [✕ Decline] buttons (30 s)
 *  B clicks Accept:
 *    → socket.emit("directChatAccept", { toId: A.id, room })
 *    → backend puts both sockets in room → emits "chatStarted" to both
 *    → B navigates to /chat
 *  B clicks Decline:
 *    → socket.emit("directChatDecline", { toId: A.id, room })
 *    → backend emits "directChatDeclined" to A
 *    → A's ChatPage shows error toast and returns to idle
 */
import {
  createContext, useContext, useEffect, useRef,
  useState, useCallback,
} from "react";
import { io } from "socket.io-client";
import { useNavigate } from "react-router-dom";
import { useAuth } from "./AuthContext";
import { useToastHelpers } from "./Toast";
import { SOCKET_URL } from "./config";

const SocketContext = createContext(null);

export function SocketProvider({ children }) {
  const { user }  = useAuth();
  const toast     = useToastHelpers();
  const navigate  = useNavigate();
  const socketRef = useRef(null);

  const [connected,   setConnected]   = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);

  // Shared ref so ChatPage can read the last "chatStarted" payload
  // delivered by a direct-chat accept while ChatPage is mounting
  const lastChatStartedRef = useRef(null);

  // ── Connect / reconnect when auth state changes ─────────────────────────
  useEffect(() => {
    // No user → disconnect and stop
    if (!user) {
      if (socketRef.current) {
        socketRef.current.disconnect();
        socketRef.current = null;
        setConnected(false);
      }
      return;
    }

    // Already have a live socket → nothing to do
    if (socketRef.current?.connected) return;

    // Tear down any stale / disconnected socket first
    if (socketRef.current) {
      socketRef.current.disconnect();
      socketRef.current = null;
    }

    // ── Create socket ─────────────────────────────────────────────────────
    const socket = io(window.location.origin, {
      withCredentials : true,          // send httpOnly cookie
      transports      : ["polling", "websocket"], // polling FIRST for auth
      reconnection         : true,
      reconnectionAttempts : 15,
      reconnectionDelay    : 1000,
      reconnectionDelayMax : 5000,
    });
    socketRef.current = socket;

    // ── Connection lifecycle ──────────────────────────────────────────────
    socket.on("connect", () => {
      console.log("[Socket] connected", socket.id);
      setConnected(true);
      socket.emit("getInterests");
    });

    socket.on("connect_error", (err) => {
      console.error("[Socket] connect_error:", err.message);
      setConnected(false);
    });

    socket.on("disconnect", (reason) => {
      console.log("[Socket] disconnected:", reason);
      setConnected(false);
    });

    // ── Unread badge ──────────────────────────────────────────────────────
    socket.on("unreadNotifications", ({ count }) => {
      setUnreadCount(count ?? 0);
    });

    // ── General push notifications → toast ───────────────────────────────
    socket.on("notification", ({ notification }) => {
      if (!notification) return;
      const TYPE_MAP = {
        follow:            "follow",
        unfollow:          "info",
        like_post:         "like",
        dislike_post:      "info",
        comment:           "message",
        rank_up:           "rank",
        rank_down:         "info",
        friend_added:      "friend",
        post_by_following: "message",
        like_comment:      "like",
      };
      const sender = notification.sender?.username
        ? `${notification.sender.username} ` : "";
      const kind = TYPE_MAP[notification.type] ?? "notif";
      toast[kind]?.(`${sender}${notification.message}`, 4000);
      setUnreadCount((c) => c + 1);
    });

    // ── Friend presence ───────────────────────────────────────────────────
    socket.on("userOnline",  ({ username }) => toast.notif(`${username} is now online`, 2500));
    socket.on("userOffline", ({ username }) => toast.notif(`${username} went offline`,  2500));

    // ── Follow / rank updates ─────────────────────────────────────────────
    socket.on("followUpdate", ({ username, action }) => {
      if (!username) return;
      if (action === "followed")   toast.follow(`${username} started following you`);
      if (action === "unfollowed") toast.notif(`${username} unfollowed you`);
    });

    socket.on("rankUpdated", ({ newRank, action }) => {
      if (action === "liked")   toast.rank(`Someone liked you! Rank ★ ${newRank}`);
      if (action === "unliked") toast.notif(`Someone unliked you. Rank ★ ${newRank}`);
    });

    // ── DIRECT CHAT REQUEST — received by User B ──────────────────────────
    socket.on("directChatRequest", ({ fromId, fromName, room }) => {
      console.log("[Socket] directChatRequest from:", fromName, fromId);

      toast.action(
        `${fromName || "A friend"} wants to chat with you!`,
        [
          {
            label : "✓ Accept",
            style : "primary",
            fn    : () => {
              // Tell server we accept → it will emit "chatStarted" to both
              socket.emit("directChatAccept", { toId: fromId, room });
              // Navigate to /chat; ChatPage listens for "chatStarted"
              navigate("/chat", {
                state: { friendId: fromId, friendName: fromName, directRoom: room },
              });
            },
          },
          {
            label : "✕ Decline",
            style : "secondary",
            fn    : () => {
              socket.emit("directChatDecline", { toId: fromId, room });
              toast.notif(`Declined chat request from ${fromName}`);
            },
          },
        ],
        30_000,
      );
    });

    // ── DIRECT CHAT DECLINED — received by User A ─────────────────────────
    socket.on("directChatDeclined", ({ byName }) => {
      toast.error(`${byName || "Friend"} declined your chat request.`);
    });

    // ── DIRECT CHAT CANCELLED — received by User B ────────────────────────
    socket.on("directChatCancelled", ({ byName }) => {
      toast.notif(`${byName || "Friend"} cancelled their chat request.`);
    });

    // ── Friend is offline ─────────────────────────────────────────────────
    socket.on("directChatUserOffline", () => {
      toast.warning("That friend is currently offline. Try again later.");
    });

    // ── Cleanup listeners on unmount / user change ────────────────────────
    return () => {
      socket.off("connect");
      socket.off("connect_error");
      socket.off("disconnect");
      socket.off("unreadNotifications");
      socket.off("notification");
      socket.off("userOnline");
      socket.off("userOffline");
      socket.off("followUpdate");
      socket.off("rankUpdated");
      socket.off("directChatRequest");
      socket.off("directChatDeclined");
      socket.off("directChatCancelled");
      socket.off("directChatUserOffline");
      // NOTE: we do NOT call socket.disconnect() here — the socket must
      // survive page navigation. It is only disconnected when user logs out
      // (user becomes null above).
    };
  }, [user]); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Send a direct chat request to a friend ──────────────────────────────
  const sendDirectChatRequest = useCallback(
    (friendId, friendName) => {
      const socket = socketRef.current;
      if (!socket?.connected) {
        toast.error("Not connected to server.");
        return null;
      }
      const myId = user?._id || user?.id;
      if (!myId) { toast.error("Not logged in."); return null; }
      if (friendId === myId) { toast.error("Cannot chat with yourself."); return null; }

      // Deterministic room — same formula as backend matchmaking
      const room = [myId, friendId].sort().join("_");
      socket.emit("directChatRequest", { toId: friendId, room });
      toast.notif(`Chat request sent to ${friendName || "friend"}…`);
      return room;
    },
    [user], // eslint-disable-line
  );

  // ── Cancel an outgoing request ───────────────────────────────────────────
  const cancelDirectChatRequest = useCallback(
    (friendId) => {
      const socket = socketRef.current;
      if (!socket?.connected) return;
      const myId = user?._id || user?.id;
      if (!myId) return;
      const room = [myId, friendId].sort().join("_");
      socket.emit("directChatCancel", { toId: friendId, room });
    },
    [user], // eslint-disable-line
  );

  // ── Mark all notifications as read ──────────────────────────────────────
  const markNotificationsRead = useCallback(() => {
    socketRef.current?.emit("markNotificationsRead", { notificationIds: [] });
    setUnreadCount(0);
  }, []);

  // ── Generic helpers so pages can add their own listeners ────────────────
  const emit      = useCallback((ev, data) => socketRef.current?.emit(ev, data), []);
  const on        = useCallback((ev, fn)   => { socketRef.current?.on(ev, fn);  }, []);
  const off       = useCallback((ev, fn)   => { socketRef.current?.off(ev, fn); }, []);
  const getSocket = useCallback(() => socketRef.current, []);

  return (
    <SocketContext.Provider value={{
      socket              : socketRef,   // ref — always current socket
      connected,
      unreadCount,
      setUnreadCount,
      markNotificationsRead,
      sendDirectChatRequest,
      cancelDirectChatRequest,
      lastChatStartedRef,
      emit,
      on,
      off,
      getSocket,
    }}>
      {children}
    </SocketContext.Provider>
  );
}

export function useSocket() {
  const ctx = useContext(SocketContext);
  if (!ctx) throw new Error("useSocket must be used inside <SocketProvider>");
  return ctx;
}
