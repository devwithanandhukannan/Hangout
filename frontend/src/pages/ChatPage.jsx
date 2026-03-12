/**
 * ChatPage — random matchmaking + direct friend chat + WebRTC video
 *
 * chatStatus values:
 *   idle           → not connected; show GO / "Send request" button
 *   waiting_accept → User A sent directChatRequest, waiting for B to accept
 *   searching      → in random matchmaking queue
 *   chatting       → connected to a partner
 *   partner_left   → partner disconnected / left
 */
import { useState, useRef, useEffect, useCallback } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { useAuth }   from "../AuthContext";
import { useSocket } from "../SocketContext";
import { useToastHelpers } from "../Toast";

const RTC_CONFIG = { iceServers: [{ urls: "stun:stun.l.google.com:19302" }] };

export default function ChatPage() {
  const { user }  = useAuth();
  const {
    socket: socketRef,
    connected,
    sendDirectChatRequest,
    cancelDirectChatRequest,
  } = useSocket();
  const toast    = useToastHelpers();
  const navigate = useNavigate();
  const location = useLocation();

  const myUserId   = user?._id || user?.id || "";
  const myUsername = user?.username || "You";

  // ── Navigation state (set by Dashboard/Feed when clicking "Chat") ───────
  const friendId   = location.state?.friendId   ?? null;
  const friendName = location.state?.friendName  ?? null;
  // directRoom is present when User A already sent the request before navigating
  const directRoom = location.state?.directRoom  ?? null;

  // ── WebRTC refs ──────────────────────────────────────────────────────────
  const pcRef         = useRef(null);
  const localStream   = useRef(null);
  const localVideoRef = useRef(null);
  const remoteVideoRef= useRef(null);

  // ── Misc refs ────────────────────────────────────────────────────────────
  const msgEndRef    = useRef(null);
  const typingTimer  = useRef(null);
  const flashTimer   = useRef(null);
  const chatDataRef  = useRef({});   // { idx: { user, message, time } }
  const msgIndexRef  = useRef(0);
  const roomRef      = useRef(null);
  const partnerIdRef = useRef(null);

  // ── UI state ─────────────────────────────────────────────────────────────
  const [mode,           setMode]           = useState("video"); // "video"|"chat"
  const [micOn,          setMicOn]          = useState(true);
  const [camOn,          setCamOn]          = useState(true);
  const [bgFlash,        setBgFlash]        = useState(false);
  const [messages,       setMessages]       = useState([]);
  const [input,          setInput]          = useState("");
  const [saving,         setSaving]         = useState(false);
  const [saveMsg,        setSaveMsg]        = useState("");
  const [uploadOpen,     setUploadOpen]     = useState(false);
  const [fileName,       setFileName]       = useState("");
  const [videoActive,    setVideoActive]    = useState(false);
  const [partnerTyping,  setPartnerTyping]  = useState(false);

  // ── Match state ───────────────────────────────────────────────────────────
  // idle | waiting_accept | searching | chatting | partner_left
  const [chatStatus,      setChatStatus]      = useState("idle");
  const [room,            setRoom]            = useState(null);
  const [partnerId,       setPartnerId]       = useState(null);
  const [partnerUsername, setPartnerUsername] = useState("");
  const [matchType,       setMatchType]       = useState(null);
  const [commonInterests, setCommonInterests] = useState([]);
  const [liked,           setLiked]           = useState(false);
  const [followed,        setFollowed]        = useState(false);
  const [myRank,          setMyRank]          = useState(
    user?.rank?.count ?? user?.rank ?? 0
  );

  // Sync refs with state
  useEffect(() => { roomRef.current      = room;      }, [room]);
  useEffect(() => { partnerIdRef.current = partnerId; }, [partnerId]);

  // ── Stop video call ───────────────────────────────────────────────────────
  const stopVideo = useCallback(() => {
    if (pcRef.current)       { pcRef.current.close(); pcRef.current = null; }
    if (localStream.current) {
      localStream.current.getTracks().forEach((t) => t.stop());
      localStream.current = null;
    }
    if (localVideoRef.current)  localVideoRef.current.srcObject  = null;
    if (remoteVideoRef.current) remoteVideoRef.current.srcObject = null;
    setVideoActive(false);
  }, []);

  // ── Fetch partner username from /api/user/:id ─────────────────────────────
  const resolveUsername = useCallback(async (pid) => {
    if (!pid) return;
    try {
      const res  = await fetch(`/api/user/${pid}`, { credentials: "include" });
      const data = await res.json();
      setPartnerUsername(data.username || `User#${pid.slice(-4)}`);
    } catch {
      setPartnerUsername(`User#${pid.slice(-4)}`);
    }
  }, []);

  // ── Reset per-session state ───────────────────────────────────────────────
  const resetSession = useCallback(() => {
    setMessages([]);
    setLiked(false);
    setFollowed(false);
    setPartnerUsername("");
    setCommonInterests([]);
    setPartnerTyping(false);
    chatDataRef.current = {};
    msgIndexRef.current = 0;
  }, []);

  // ── Enter chatting state ──────────────────────────────────────────────────
  const enterChat = useCallback((r, pid, mt, ci, nameHint) => {
    // Guard: never match with yourself
    if (pid === myUserId) {
      socketRef.current?.emit("leaveChat", { partnerId: pid });
      toast.error("Matched with yourself — retrying…");
      setChatStatus("idle");
      return;
    }
    roomRef.current      = r;
    partnerIdRef.current = pid;
    setRoom(r);
    setPartnerId(pid);
    setMatchType(mt || "random");
    setCommonInterests(Array.isArray(ci) ? ci : []);
    setChatStatus("chatting");
    resetSession();
    stopVideo();
    if (nameHint) setPartnerUsername(nameHint);
    else          resolveUsername(pid);

    const info = Array.isArray(ci) && ci.length
      ? `Matched on: ${ci.map((i) => `#${i}`).join(", ")}`
      : mt === "direct" ? "Direct friend chat started"
      : `Matched via ${mt || "random"}`;
    toast.success(info, 4000);
  }, [myUserId, resetSession, stopVideo, resolveUsername]); // eslint-disable-line

  // ── Socket listeners ──────────────────────────────────────────────────────
  useEffect(() => {
    const socket = socketRef.current;
    if (!socket) return;

    // If navigated with directRoom → we are the initiator (User A)
    if (directRoom && friendId && chatStatus === "idle") {
      setChatStatus("waiting_accept");
      setPartnerUsername(friendName || "Friend");
    }

    // ── Matchmaking ───────────────────────────────────────────────────────
    const onWaiting   = () => setChatStatus("searching");
    const onCancelled = () => setChatStatus("idle");

    const onChatStarted = ({ room: r, partnerId: pid, matchType: mt, commonInterests: ci }) => {
      const nameHint = (pid === friendId) ? friendName : null;
      enterChat(r, pid, mt, ci, nameHint);
    };

    // ── Messages ──────────────────────────────────────────────────────────
    const onPrivateMsg = ({ senderId, text, timestamp }) => {
      // Deduplicate: server echoes to the whole room including sender
      if (senderId === myUserId) return;
      const time = timestamp
        ? new Date(timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
        : new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      const idx = msgIndexRef.current;
      chatDataRef.current[idx] = { user: "partner", message: text, time };
      msgIndexRef.current += 1;
      setMessages((p) => [...p, { id: Date.now() + Math.random(), from: "partner", text, time }]);
      setPartnerTyping(false);
    };

    const onTyping = ({ isTyping }) => setPartnerTyping(!!isTyping);

    // ── Partner left ──────────────────────────────────────────────────────
    const onGone = () => {
      toast.notif("Partner left the chat");
      setChatStatus("partner_left");
      setRoom(null); setPartnerId(null);
      roomRef.current = null; partnerIdRef.current = null;
      setPartnerTyping(false);
      stopVideo();
    };

    // ── Direct chat declined (User A receives) ────────────────────────────
    const onDeclined = ({ byName }) => {
      toast.error(`${byName || "Friend"} declined your request.`);
      setChatStatus("idle");
    };

    // ── Follow result ─────────────────────────────────────────────────────
    const onFollowed = ({ message, isFriend }) => {
      const isNowFollowing = !message?.toLowerCase().includes("unfollow");
      setFollowed(isNowFollowing);
      if (isFriend) toast.friend("You're now friends! 🎉");
      else toast.follow(message || "Follow updated");
    };
    const onFollowStatus = ({ followerId, action, isFriend }) => {
      if (followerId !== myUserId) return;
      setFollowed(action === "followed");
      if (isFriend) toast.friend("You're now friends! 🎉");
    };

    // ── Rank / like result ────────────────────────────────────────────────
    const onRanked = ({ newRank, action }) => {
      if (action === "liked")   toast.like(`Liked! Their rank is now ★ ${newRank}`);
      else                      toast.notif(`Unliked. Rank: ★ ${newRank}`);
    };
    const onRankInChat = ({ userId, newRank }) => {
      if (userId === myUserId) {
        setMyRank(newRank);
        toast.rank(`Your rank is now ★ ${newRank}`);
      }
    };
    const onRankUpdated = ({ newRank }) => setMyRank(newRank);

    // ── WebRTC signal ─────────────────────────────────────────────────────
    const onSignal = async ({ data }) => {
      try {
        if (!pcRef.current) {
          // We are the answering side — start receiver flow
          if (data.sdp?.type === "offer") {
            await startVideoReceiver(data.sdp, socket);
          }
          return;
        }
        if (data.sdp) {
          await pcRef.current.setRemoteDescription(new RTCSessionDescription(data.sdp));
          if (data.sdp.type === "offer") {
            const answer = await pcRef.current.createAnswer();
            await pcRef.current.setLocalDescription(answer);
            socket.emit("signal", { data: { sdp: pcRef.current.localDescription } });
          }
        } else if (data.candidate) {
          await pcRef.current.addIceCandidate(new RTCIceCandidate(data.candidate));
        }
      } catch (err) { console.error("Signal error:", err); }
    };

    socket.on("waitingForPartner",   onWaiting);
    socket.on("waitingCancelled",    onCancelled);
    socket.on("chatStarted",         onChatStarted);
    socket.on("privateMessage",      onPrivateMsg);
    socket.on("partnerTyping",       onTyping);
    socket.on("partnerLeft",         onGone);
    socket.on("partnerDisconnected", onGone);
    socket.on("directChatDeclined",  onDeclined);
    socket.on("followed",            onFollowed);
    socket.on("followStatusUpdate",  onFollowStatus);
    socket.on("ranked",              onRanked);
    socket.on("rankUpdateInChat",    onRankInChat);
    socket.on("rankUpdated",         onRankUpdated);
    socket.on("signal",              onSignal);

    return () => {
      socket.off("waitingForPartner",   onWaiting);
      socket.off("waitingCancelled",    onCancelled);
      socket.off("chatStarted",         onChatStarted);
      socket.off("privateMessage",      onPrivateMsg);
      socket.off("partnerTyping",       onTyping);
      socket.off("partnerLeft",         onGone);
      socket.off("partnerDisconnected", onGone);
      socket.off("directChatDeclined",  onDeclined);
      socket.off("followed",            onFollowed);
      socket.off("followStatusUpdate",  onFollowStatus);
      socket.off("ranked",              onRanked);
      socket.off("rankUpdateInChat",    onRankInChat);
      socket.off("rankUpdated",         onRankUpdated);
      socket.off("signal",              onSignal);
    };
  // directRoom / friendId / friendName are stable navigation state values
  }, [connected, myUserId]); // eslint-disable-line

  // Scroll to bottom on new message
  useEffect(() => {
    msgEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, partnerTyping]);

  // ── WebRTC helpers ─────────────────────────────────────────────────────────
  const buildPC = (socket, stream) => {
    const pc = new RTCPeerConnection(RTC_CONFIG);
    pcRef.current = pc;
    stream.getTracks().forEach((t) => pc.addTrack(t, stream));
    pc.ontrack = (e) => {
      if (remoteVideoRef.current) remoteVideoRef.current.srcObject = e.streams[0];
    };
    pc.onicecandidate = (e) => {
      if (e.candidate) socket.emit("signal", { data: { candidate: e.candidate } });
    };
    return pc;
  };

  const startVideoReceiver = async (offerSdp, socket) => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
      localStream.current = stream;
      if (localVideoRef.current) localVideoRef.current.srcObject = stream;
      const pc = buildPC(socket, stream);
      await pc.setRemoteDescription(new RTCSessionDescription(offerSdp));
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      socket.emit("signal", { data: { sdp: pc.localDescription } });
      applyAV(stream);
      setVideoActive(true);
    } catch (err) { toast.error("Camera/mic: " + err.message); }
  };

  const startVideo = useCallback(async () => {
    const socket = socketRef.current;
    if (!socket || !roomRef.current) return;
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
      localStream.current = stream;
      if (localVideoRef.current) localVideoRef.current.srcObject = stream;
      const pc = buildPC(socket, stream);
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      socket.emit("signal", { data: { sdp: offer } });
      applyAV(stream);
      setVideoActive(true);
      toast.success("Video call started — waiting for partner…");
    } catch (err) { toast.error("Camera/mic: " + err.message); }
  }, []); // eslint-disable-line

  const applyAV = (stream) => {
    stream.getAudioTracks().forEach((t) => { t.enabled = micOn; });
    stream.getVideoTracks().forEach((t) => { t.enabled = camOn; });
  };

  const toggleMic = useCallback(() => {
    setMicOn((prev) => {
      const next = !prev;
      localStream.current?.getAudioTracks().forEach((t) => { t.enabled = next; });
      return next;
    });
  }, []);

  const toggleCam = useCallback(() => {
    setCamOn((prev) => {
      const next = !prev;
      localStream.current?.getVideoTracks().forEach((t) => { t.enabled = next; });
      return next;
    });
  }, []);

  // ── Matchmaking actions ────────────────────────────────────────────────────
  const findChat = useCallback(() => {
    const socket = socketRef.current;
    if (!socket?.connected) { toast.error("Not connected — please wait…"); return; }
    setChatStatus("searching");
    setRoom(null); setPartnerId(null);
    resetSession();
    socket.emit("findChat");
  }, [resetSession]); // eslint-disable-line

  const cancelWaiting = useCallback(() => {
    socketRef.current?.emit("cancelWaiting");
    setChatStatus("idle");
  }, []);

  const cancelDirectRequest = useCallback(() => {
    if (friendId) cancelDirectChatRequest(friendId);
    setChatStatus("idle");
  }, [friendId, cancelDirectChatRequest]);

  const skipChat = useCallback(() => {
    const pid = partnerIdRef.current;
    if (socketRef.current && pid) socketRef.current.emit("leaveChat", { partnerId: pid });
    stopVideo();
    setRoom(null); setPartnerId(null);
    resetSession();
    findChat(); // immediately re-queue
  }, [findChat, stopVideo, resetSession]);

  const endChat = useCallback(() => {
    const pid = partnerIdRef.current;
    if (socketRef.current && pid) socketRef.current.emit("leaveChat", { partnerId: pid });
    if (chatStatus === "waiting_accept" && friendId) cancelDirectChatRequest(friendId);
    stopVideo();
    navigate("/dashboard");
  }, [navigate, stopVideo, chatStatus, friendId, cancelDirectChatRequest]);

  // ── Messaging ─────────────────────────────────────────────────────────────
  const handleSend = useCallback((e) => {
    e?.preventDefault();
    const text   = input.trim();
    const socket = socketRef.current;
    if (!text || !roomRef.current || !socket) return;
    const time = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    const idx  = msgIndexRef.current;
    chatDataRef.current[idx] = { user: "me", message: text, time };
    msgIndexRef.current += 1;
    setMessages((p) => [...p, { id: Date.now(), from: "me", text, time }]);
    socket.emit("privateMessage", { text, room: roomRef.current });
    socket.emit("typing", { room: roomRef.current, isTyping: false });
    setInput("");
    clearTimeout(typingTimer.current);
  }, [input]); // eslint-disable-line

  const handleInputChange = useCallback((val) => {
    setInput(val);
    const socket = socketRef.current;
    if (!socket || !roomRef.current) return;
    socket.emit("typing", { room: roomRef.current, isTyping: val.length > 0 });
    clearTimeout(typingTimer.current);
    typingTimer.current = setTimeout(() => {
      socket.emit("typing", { room: roomRef.current, isTyping: false });
    }, 2000);
  }, []);

  // ── Like / Rank ────────────────────────────────────────────────────────────
  const handleLike = useCallback(() => {
    const socket = socketRef.current;
    const pid    = partnerIdRef.current;
    if (!socket || !pid || pid === myUserId) return;
    socket.emit("like");
    setLiked((prev) => {
      const next = !prev;
      if (next) {
        setBgFlash(true);
        clearTimeout(flashTimer.current);
        flashTimer.current = setTimeout(() => setBgFlash(false), 3000);
      } else {
        setBgFlash(false);
        clearTimeout(flashTimer.current);
      }
      return next;
    });
  }, [myUserId]);

  // ── Follow ─────────────────────────────────────────────────────────────────
  const handleFollow = useCallback(() => {
    const socket = socketRef.current;
    const pid    = partnerIdRef.current;
    if (!socket || !pid || pid === myUserId) return;
    socket.emit("follow");
    setFollowed((p) => !p);
  }, [myUserId]);

  // ── Save chat ──────────────────────────────────────────────────────────────
  const handleSaveChat = useCallback(async () => {
    const pid      = partnerIdRef.current;
    const chatData = chatDataRef.current;
    if (!pid) { toast.warning("No partner to save with."); return; }
    if (!Object.keys(chatData).length) { toast.warning("Nothing to save yet."); return; }
    setSaving(true);
    try {
      const res  = await fetch("/api/save-chat", {
        method      : "POST",
        credentials : "include",
        headers     : { "Content-Type": "application/json" },
        body        : JSON.stringify({ partnerId: pid, chatData }),
      });
      const data = await res.json();
      if (data.success) toast.success("Chat saved!");
      else              toast.error(data.message || "Save failed");
    } catch { toast.error("Save failed"); }
    finally { setSaving(false); }
  }, []);

  // ── Derived display values ─────────────────────────────────────────────────
  const partnerInitial = partnerUsername?.[0]?.toUpperCase() || "?";
  const partnerDisplay = partnerUsername || (partnerId ? `User#${partnerId.slice(-4)}` : "");

  const badge = (() => {
    if (!connected)                    return { text: "Connecting…",          color: "text-yellow-400" };
    if (chatStatus === "idle")         return { text: "Ready",                color: "text-gray-400"   };
    if (chatStatus === "waiting_accept") return { text: "Waiting for accept…",color: "text-blue-400"   };
    if (chatStatus === "searching")    return { text: "Searching…",           color: "text-yellow-400" };
    if (chatStatus === "chatting")     return { text: `Connected · ${matchType || ""}`, color: "text-green-400" };
    if (chatStatus === "partner_left") return { text: "Partner left",         color: "text-red-400"    };
    return { text: "", color: "" };
  })();

  // ── Send direct request helper ─────────────────────────────────────────────
  const sendRequest = useCallback(() => {
    if (!friendId) return;
    const r = sendDirectChatRequest(friendId, friendName);
    if (r) setChatStatus("waiting_accept");
  }, [friendId, friendName, sendDirectChatRequest]);

  // ─────────────────────────────────────────────────────────────────────────
  return (
    <div
      className="h-screen flex flex-col text-white antialiased overflow-hidden transition-colors duration-700"
      style={{ backgroundColor: bgFlash ? "#1a0000" : "#000000" }}
    >
      {/* ══ HEADER ══════════════════════════════════════════════════════════ */}
      <header className="flex-shrink-0 border-b border-white/10 bg-black/50 backdrop-blur-xl">
        <div className="px-4 sm:px-6 py-3 flex items-center justify-between gap-3 flex-wrap">
          {/* Left */}
          <div className="flex items-center gap-3 min-w-0">
            <button
              onClick={endChat}
              className="h-8 w-8 flex-shrink-0 flex items-center justify-center rounded-full border border-white/40 text-sm hover:bg-white hover:text-black transition"
            >←</button>
            <span className="font-semibold text-sm tracking-tight">Hangout</span>
            <span className={`text-[11px] flex-shrink-0 ${badge.color}`}>{badge.text}</span>
          </div>

          {/* Right actions */}
          <div className="flex items-center gap-2 flex-wrap justify-end">
            <button
              onClick={handleSaveChat}
              disabled={saving || chatStatus !== "chatting"}
              className="px-3 py-1 rounded-full border border-white text-xs hover:bg-white hover:text-black transition disabled:opacity-40"
            >
              {saving ? "Saving…" : "Save chat"}
            </button>

            {chatStatus === "idle" && (
              <button
                onClick={friendId ? sendRequest : findChat}
                disabled={!connected}
                className="px-3 py-1 rounded-full border border-white text-xs hover:bg-white hover:text-black transition disabled:opacity-40"
              >
                {friendId ? `Chat with ${friendName || "friend"}` : "Find match"}
              </button>
            )}

            {chatStatus === "searching" && (
              <button onClick={cancelWaiting}
                className="px-3 py-1 rounded-full border border-yellow-400 text-yellow-400 text-xs hover:bg-yellow-400 hover:text-black transition">
                Cancel search
              </button>
            )}

            {chatStatus === "waiting_accept" && (
              <button onClick={cancelDirectRequest}
                className="px-3 py-1 rounded-full border border-red-400 text-red-400 text-xs hover:bg-red-400 hover:text-black transition">
                Cancel request
              </button>
            )}

            {chatStatus === "chatting" && (
              <button onClick={skipChat}
                className="px-3 py-1 rounded-full border border-white text-xs hover:bg-white hover:text-black transition">
                Skip
              </button>
            )}

            {chatStatus === "partner_left" && (
              <button onClick={friendId ? sendRequest : findChat}
                className="px-3 py-1 rounded-full border border-white text-xs hover:bg-white hover:text-black transition">
                {friendId ? "Request again" : "Find new match"}
              </button>
            )}

            <button
              onClick={() => setMode((m) => m === "video" ? "chat" : "video")}
              className="px-3 py-1 rounded-full border border-white text-xs hover:bg-white hover:text-black transition"
            >
              {mode === "video" ? "Text only" : "Video mode"}
            </button>
          </div>
        </div>
      </header>

      {/* ══ MAIN ════════════════════════════════════════════════════════════ */}
      <main className="flex-1 min-h-0 px-3 sm:px-4 py-3 flex gap-3 overflow-hidden">

        {/* ════ VIDEO PANEL ════════════════════════════════════════════════ */}
        {mode === "video" && (
          <section className="flex-1 min-w-0 min-h-0 flex flex-col bg-white/5 border border-white/15 rounded-3xl backdrop-blur-xl overflow-hidden px-4 sm:px-5 py-4">

            {/* Partner header */}
            <div className="flex-shrink-0 flex items-center justify-between gap-3 mb-3">
              <div className="flex items-center gap-3 min-w-0">
                <div className="h-10 w-10 flex-shrink-0 rounded-full bg-white text-black flex items-center justify-center text-sm font-bold">
                  {chatStatus === "chatting" ? partnerInitial
                    : chatStatus === "waiting_accept" ? (friendName?.[0]?.toUpperCase() || "?")
                    : "–"}
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-semibold text-sm truncate">
                      {chatStatus === "chatting"      ? partnerDisplay
                        : chatStatus === "waiting_accept" ? `Waiting for ${friendName || "friend"}…`
                        : chatStatus === "searching"      ? "Searching…"
                        : chatStatus === "partner_left"   ? "Partner left"
                        : friendId ? `Chat with ${friendName || "friend"}` : "Start a chat"}
                    </span>
                    {chatStatus === "chatting" && (
                      <button
                        onClick={handleFollow}
                        className={`flex-shrink-0 px-2 py-0.5 rounded-full border text-[11px] transition ${
                          followed ? "bg-white text-black border-white" : "border-white hover:bg-white hover:text-black"
                        }`}
                      >
                        {followed ? "Following ✓" : "Follow"}
                      </button>
                    )}
                  </div>
                  <p className="text-[11px] text-gray-400 mt-0.5 truncate">
                    {chatStatus === "chatting"
                      ? commonInterests.length > 0
                        ? `Common: ${commonInterests.map((i) => `#${i}`).join(" ")}`
                        : matchType === "direct" ? "Direct friend chat"
                        : `Matched via ${matchType ?? "random"}`
                      : chatStatus === "waiting_accept" ? "Waiting for acceptance…"
                      : chatStatus === "searching"      ? "Looking for someone with your interests…"
                      : chatStatus === "partner_left"   ? "Your partner disconnected."
                      : friendId ? "Send a chat request to start." : "Click GO to find a match."}
                  </p>
                </div>
              </div>
              {/* Your rank */}
              <div className="flex-shrink-0 text-right">
                <div className="text-[10px] text-gray-500">Your rank</div>
                <div className="text-sm font-bold text-yellow-400">★ {myRank}</div>
              </div>
            </div>

            {/* Video area */}
            <div className="flex-1 min-h-0 flex flex-col">
              <div className="relative flex-1 min-h-0 rounded-2xl bg-white/8 border border-white/15 overflow-hidden flex items-center justify-center">
                {/* Ambient glow */}
                <div className="absolute inset-0 pointer-events-none opacity-25 bg-[radial-gradient(circle_at_15%_15%,rgba(255,255,255,0.5),transparent_55%)]" />

                {/* Remote video (fullscreen in panel) */}
                <video
                  ref={remoteVideoRef} autoPlay playsInline
                  className={`absolute inset-0 w-full h-full object-cover ${videoActive ? "block" : "hidden"}`}
                />

                {/* Overlay when no video */}
                {!videoActive && (
                  <div className="relative z-10 flex flex-col items-center gap-4 px-6 text-center">
                    {chatStatus === "searching" && (
                      <>
                        <div className="h-12 w-12 rounded-full border-2 border-white border-t-transparent animate-spin" />
                        <p className="text-sm text-gray-300">Finding your match…</p>
                      </>
                    )}
                    {chatStatus === "waiting_accept" && (
                      <>
                        <div className="h-12 w-12 rounded-full border-2 border-blue-400 border-t-transparent animate-spin" />
                        <p className="text-sm text-blue-300">
                          Waiting for {friendName || "friend"} to accept…
                        </p>
                        <p className="text-[11px] text-gray-500">They'll see a notification.</p>
                        <button onClick={cancelDirectRequest}
                          className="text-xs text-red-400 border border-red-400/40 px-4 py-1.5 rounded-full hover:bg-red-400/10 transition">
                          Cancel request
                        </button>
                      </>
                    )}
                    {chatStatus === "chatting" && (
                      <>
                        <p className="text-xs text-gray-400">
                          Camera appears here when video call starts.
                        </p>
                        <button onClick={startVideo}
                          className="px-6 py-2.5 rounded-full bg-white text-black text-sm font-semibold hover:bg-gray-200 transition">
                          📹 Start Video Call
                        </button>
                      </>
                    )}
                    {chatStatus === "partner_left" && (
                      <div className="flex flex-col items-center gap-3">
                        <p className="text-sm text-gray-400">Partner left.</p>
                        <button onClick={friendId ? sendRequest : findChat}
                          className="px-5 py-2 rounded-full bg-white text-black text-xs font-semibold hover:bg-gray-200 transition">
                          {friendId ? "Request again" : "Find new match"}
                        </button>
                      </div>
                    )}
                    {chatStatus === "idle" && (
                      <button
                        onClick={friendId ? sendRequest : findChat}
                        disabled={!connected}
                        className="w-24 h-24 rounded-full bg-white text-black text-2xl font-bold hover:scale-105 transition-transform shadow-[0_0_40px_rgba(255,255,255,0.2)] disabled:opacity-40"
                      >
                        {friendId ? "Chat" : "GO"}
                      </button>
                    )}
                  </div>
                )}

                {/* End video call button */}
                {videoActive && (
                  <button onClick={stopVideo}
                    className="absolute top-3 right-3 z-20 px-3 py-1 rounded-full bg-red-600 text-white text-xs hover:bg-red-700 transition">
                    End Call
                  </button>
                )}

                {/* Local PIP */}
                <div className={`absolute bottom-3 right-3 z-10 w-32 h-24 rounded-xl border border-white/20 overflow-hidden bg-black flex items-center justify-center ${!videoActive ? "hidden" : ""}`}>
                  <video ref={localVideoRef} autoPlay muted playsInline
                    className={`w-full h-full object-cover ${camOn ? "block" : "hidden"}`} />
                  {!camOn && <span className="text-[11px] text-gray-400">Cam off</span>}
                </div>
              </div>

              {/* Controls row */}
              <div className="flex-shrink-0 mt-3 flex items-center justify-between gap-3 flex-wrap">
                <div className="flex items-center gap-2 text-xs">
                  <button onClick={toggleMic}
                    className={`px-3 py-1.5 rounded-full border flex items-center gap-1.5 transition ${
                      micOn ? "bg-white text-black border-white" : "bg-white/10 text-white border-white/30"
                    }`}>
                    🎙 {micOn ? "Mic on" : "Muted"}
                  </button>
                  <button onClick={toggleCam}
                    className={`px-3 py-1.5 rounded-full border flex items-center gap-1.5 transition ${
                      camOn ? "bg-white text-black border-white" : "bg-white/10 text-white border-white/30"
                    }`}>
                    📹 {camOn ? "Cam on" : "Cam off"}
                  </button>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={handleLike}
                    disabled={chatStatus !== "chatting" || partnerId === myUserId}
                    title={liked ? "Unlike — removes heart from their rank" : "Like — adds to their rank!"}
                    className={`h-9 w-9 flex items-center justify-center rounded-full border transition text-sm ${
                      liked ? "bg-red-500 border-red-500 text-white" : "border-gray-400 hover:bg-white hover:text-black"
                    } disabled:opacity-40`}
                  >
                    {liked ? "♥" : "♡"}
                  </button>
                  <button onClick={endChat}
                    className="px-4 py-1.5 rounded-full bg-white text-black text-xs font-semibold hover:bg-gray-200 transition">
                    End
                  </button>
                </div>
              </div>
            </div>
          </section>
        )}

        {/* ════ CHAT PANEL ═════════════════════════════════════════════════ */}
        <section className={`min-h-0 flex flex-col bg-white/5 border border-white/15 rounded-3xl backdrop-blur-xl overflow-hidden px-4 sm:px-5 py-4 ${
          mode === "video" ? "w-full lg:w-80 xl:w-96 flex-shrink-0" : "flex-1"
        }`}>

          {/* Panel header */}
          <div className="flex-shrink-0 flex items-center justify-between mb-3">
            <div className="min-w-0">
              <h2 className="text-sm font-semibold truncate">
                {chatStatus === "chatting" && partnerDisplay
                  ? `Chat with ${partnerDisplay}`
                  : chatStatus === "waiting_accept"
                  ? `Waiting for ${friendName || "friend"}…`
                  : "Text chat"}
              </h2>
              {chatStatus === "chatting" && commonInterests.length > 0 && (
                <p className="text-[10px] text-gray-500 truncate">
                  Common: {commonInterests.map((i) => `#${i}`).join(" ")}
                </p>
              )}
            </div>
            <span className={`text-[10px] flex-shrink-0 ml-2 ${badge.color}`}>{badge.text}</span>
          </div>

          {/* Messages */}
          <div className="flex-1 min-h-0 overflow-y-auto space-y-2 pr-1">

            {chatStatus === "idle" && (
              <div className="h-full flex flex-col items-center justify-center gap-4 text-center">
                <p className="text-gray-500 text-xs">Not connected yet.</p>
                <button
                  onClick={friendId ? sendRequest : findChat}
                  disabled={!connected}
                  className="px-6 py-2.5 rounded-full bg-white text-black text-xs font-semibold hover:bg-gray-200 disabled:opacity-40 transition"
                >
                  {friendId ? `Chat with ${friendName || "friend"}` : "Find match"}
                </button>
              </div>
            )}

            {chatStatus === "waiting_accept" && (
              <div className="h-full flex flex-col items-center justify-center gap-3 text-center">
                <div className="h-7 w-7 rounded-full border-2 border-blue-400 border-t-transparent animate-spin" />
                <p className="text-blue-300 text-xs">
                  Waiting for {friendName || "friend"} to accept…
                </p>
                <p className="text-gray-600 text-[11px]">They'll see a notification popup.</p>
                <button onClick={cancelDirectRequest}
                  className="text-[11px] text-red-400 border border-red-400/50 px-3 py-1 rounded-full hover:bg-red-400/10 transition">
                  Cancel
                </button>
              </div>
            )}

            {chatStatus === "searching" && (
              <div className="h-full flex flex-col items-center justify-center gap-3 text-center">
                <div className="h-7 w-7 rounded-full border-2 border-white border-t-transparent animate-spin" />
                <p className="text-gray-400 text-xs">Searching for someone…</p>
                <button onClick={cancelWaiting}
                  className="text-[11px] text-yellow-400 border border-yellow-400/50 px-3 py-1 rounded-full hover:bg-yellow-400/10 transition">
                  Cancel
                </button>
              </div>
            )}

            {chatStatus === "partner_left" && (
              <div className="h-full flex flex-col items-center justify-center gap-3 text-center">
                <p className="text-gray-400 text-xs">Partner left.</p>
                <button onClick={friendId ? sendRequest : findChat}
                  className="text-white underline text-xs">
                  {friendId ? "Request again" : "Find new match"}
                </button>
              </div>
            )}

            {chatStatus === "chatting" && messages.length === 0 && (
              <div className="h-full flex items-center justify-center">
                <p className="text-gray-500 text-xs">Connected! Say hello 👋</p>
              </div>
            )}

            {messages.map((msg) => (
              <div key={msg.id}>
                {msg.from === "partner" && (
                  <div className="text-[10px] text-gray-500 pl-1 mb-0.5">{partnerDisplay}</div>
                )}
                <div className={`flex ${msg.from === "me" ? "justify-end" : "justify-start"}`}>
                  <div className={`max-w-[78%] rounded-2xl px-3 py-2 break-words text-sm leading-relaxed ${
                    msg.from === "me"
                      ? "bg-white text-black"
                      : "bg-gray-900 text-white border border-white/10"
                  }`}>
                    {msg.text}
                  </div>
                </div>
                <div className={`text-[10px] text-gray-500 mt-0.5 ${
                  msg.from === "me" ? "text-right pr-1" : "pl-1"
                }`}>
                  {msg.time}
                </div>
              </div>
            ))}

            {/* Typing dots */}
            {partnerTyping && chatStatus === "chatting" && (
              <div className="flex justify-start">
                <div className="bg-gray-900 border border-white/10 rounded-2xl px-3 py-2 flex items-center gap-1">
                  <span className="h-1.5 w-1.5 rounded-full bg-gray-400 animate-bounce [animation-delay:0ms]" />
                  <span className="h-1.5 w-1.5 rounded-full bg-gray-400 animate-bounce [animation-delay:150ms]" />
                  <span className="h-1.5 w-1.5 rounded-full bg-gray-400 animate-bounce [animation-delay:300ms]" />
                </div>
              </div>
            )}
            <div ref={msgEndRef} />
          </div>

          {/* Input bar */}
          <form onSubmit={handleSend} className="flex-shrink-0 mt-3 pt-3 border-t border-white/10">
            <div className="flex items-center gap-2">
              <button type="button" onClick={() => setUploadOpen(true)}
                className="h-8 w-8 flex-shrink-0 flex items-center justify-center rounded-full border border-gray-700 hover:bg-gray-900 text-lg">
                +
              </button>
              <input
                type="text"
                placeholder={chatStatus === "chatting" ? "Type a message…" : "Connect to chat"}
                value={input}
                onChange={(e) => handleInputChange(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) handleSend(e); }}
                disabled={chatStatus !== "chatting"}
                className="flex-1 min-w-0 bg-transparent border-none outline-none text-sm placeholder:text-gray-500 disabled:opacity-40"
              />
              <button type="submit"
                disabled={chatStatus !== "chatting" || !input.trim()}
                className="flex-shrink-0 text-xs px-3 py-1.5 rounded-full bg-white text-black hover:bg-gray-200 transition disabled:opacity-40">
                Send
              </button>
            </div>
          </form>
        </section>
      </main>

      {/* ── Upload modal ─────────────────────────────────────────────────── */}
      {uploadOpen && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
          <div className="bg-black border border-white/10 rounded-2xl p-5 w-80 max-w-[90vw] backdrop-blur-xl">
            <h3 className="text-sm font-semibold mb-3">Upload image</h3>
            <input
              type="file" accept="image/*"
              onChange={(e) => { if (e.target.files?.[0]) setFileName(e.target.files[0].name); }}
              className="w-full text-xs text-gray-300 file:mr-3 file:py-1.5 file:px-3 file:rounded-full file:border-0 file:bg-white file:text-black file:text-xs"
            />
            {fileName && <p className="mt-2 text-[11px] text-gray-400">{fileName}</p>}
            <div className="mt-4 flex justify-end">
              <button onClick={() => { setUploadOpen(false); setFileName(""); }}
                className="px-3 py-1 rounded-full border border-gray-600 hover:bg-gray-900 text-xs transition">
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
