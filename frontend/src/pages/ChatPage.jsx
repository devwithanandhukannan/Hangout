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
import { 
  FaVideo, FaArrowLeft, FaHeart, FaRegHeart, FaTimes, 
  FaPaperPlane, FaUserPlus, FaUserCheck, FaMicrophone, 
  FaMicrophoneSlash, FaCamera, FaChevronRight, FaSave, FaStar
} from "react-icons/fa";
import { CgCamera, CgMic } from "react-icons/cg";
import { IoIosCloseCircle } from "react-icons/io";

const RTC_CONFIG = { iceServers: [{ urls: "stun:stun.l.google.com:19302" }] };

export default function ChatPage() {
  const { user }  = useAuth();
  const {
    socket: socketRef,
    connected,
    sendDirectChatRequest,
    cancelDirectChatRequest,
    lastChatStartedRef,
  } = useSocket();
  const toast    = useToastHelpers();
  const navigate = useNavigate();
  const location = useLocation();

  const myUserId   = user?._id || user?.id || "";
  const myUsername = user?.username || "You";

  // ── Navigation state (set by Dashboard/Feed when clicking "Chat") ───────
  const friendId   = location.state?.friendId   ?? null;
  const friendName = location.state?.friendName  ?? null;
  const directRoom = location.state?.directRoom  ?? null;
  const accepted   = location.state?.accepted    ?? false;

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
  const acceptedRoomRef = useRef(null);

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
  const [incomingCall,   setIncomingCall]   = useState(null); // { sdp } when B gets a call offer
  const [callState,      setCallState]      = useState("idle"); // "idle"|"calling"|"active"|"declined"

  // ── Match state ───────────────────────────────────────────────────────────
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
    setCallState("idle");
    setIncomingCall(null);
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

  // ── Auto-cancel outgoing request on unmount/navigation away ───────────────
  const chatStatusRef = useRef(chatStatus);
  useEffect(() => {
    chatStatusRef.current = chatStatus;
  }, [chatStatus]);

  useEffect(() => {
    return () => {
      if (chatStatusRef.current === "waiting_accept" && friendId) {
        cancelDirectChatRequest(friendId);
      }
    };
  }, [friendId, cancelDirectChatRequest]);

  // ── Socket listeners ──────────────────────────────────────────────────────
  useEffect(() => {
    const socket = socketRef.current;
    if (!socket) return;

    if (directRoom && friendId && chatStatus === "idle") {
      if (accepted) {
        setChatStatus("searching");
        if (acceptedRoomRef.current !== directRoom) {
          acceptedRoomRef.current = directRoom;
          socket.emit("directChatAccept", { toId: friendId, room: directRoom });
        }
      } else {
        setChatStatus("waiting_accept");
        setPartnerUsername(friendName || "Friend");
      }
    }

    const onWaiting   = () => setChatStatus("searching");
    const onCancelled = () => setChatStatus("idle");

    const onChatStarted = ({ room: r, partnerId: pid, matchType: mt, commonInterests: ci }) => {
      lastChatStartedRef.current = null;
      const nameHint = (pid === friendId) ? friendName : null;
      enterChat(r, pid, mt, ci, nameHint);
    };

    const onPrivateMsg = ({ senderId, text, timestamp }) => {
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

    const onGone = () => {
      toast.notif("Partner left the chat");
      setChatStatus("partner_left");
      setRoom(null); setPartnerId(null);
      roomRef.current = null; partnerIdRef.current = null;
      setPartnerTyping(false);
      stopVideo();
    };

    const onDeclined = ({ byName }) => {
      toast.error(`${byName || "Friend"} declined your request.`);
      setChatStatus("idle");
    };

    const onInvalid = () => {
      toast.error("This chat request is no longer valid or was cancelled.");
      setChatStatus("idle");
      navigate("/dashboard");
    };

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

    const onSignal = async ({ data }) => {
      try {
        if (data.declined) return;

        if (!pcRef.current) {
          if (data.sdp?.type === "offer") {
            setIncomingCall({ sdp: data.sdp });
            setCallState("incoming");
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

    const onVideoCallDeclined = () => {
      setCallState("idle");
      toast.notif(`${partnerUsername || "Partner"} declined the video call.`);
    };

    socket.on("waitingForPartner",   onWaiting);
    socket.on("waitingCancelled",    onCancelled);
    socket.on("chatStarted",         onChatStarted);
    socket.on("privateMessage",      onPrivateMsg);
    socket.on("partnerTyping",       onTyping);
    socket.on("partnerLeft",         onGone);
    socket.on("partnerDisconnected", onGone);
    socket.on("directChatDeclined",  onDeclined);
    socket.on("directChatInvalid",   onInvalid);
    socket.on("followed",            onFollowed);
    socket.on("followStatusUpdate",  onFollowStatus);
    socket.on("ranked",              onRanked);
    socket.on("rankUpdateInChat",    onRankInChat);
    socket.on("rankUpdated",         onRankUpdated);
    socket.on("signal",              onSignal);
    socket.on("videoCallDeclined",   onVideoCallDeclined);

    if (accepted && chatStatus !== "chatting") {
      const buffered = lastChatStartedRef.current;
      if (
        buffered &&
        buffered.room === directRoom &&
        buffered.partnerId
      ) {
        lastChatStartedRef.current = null;
        setTimeout(() => onChatStarted(buffered), 0);
      }
    }

    return () => {
      socket.off("waitingForPartner",   onWaiting);
      socket.off("waitingCancelled",    onCancelled);
      socket.off("chatStarted",         onChatStarted);
      socket.off("privateMessage",      onPrivateMsg);
      socket.off("partnerTyping",       onTyping);
      socket.off("partnerLeft",         onGone);
      socket.off("partnerDisconnected", onGone);
      socket.off("directChatDeclined",  onDeclined);
      socket.off("directChatInvalid",   onInvalid);
      socket.off("followed",            onFollowed);
      socket.off("followStatusUpdate",  onFollowStatus);
      socket.off("ranked",              onRanked);
      socket.off("rankUpdateInChat",    onRankInChat);
      socket.off("rankUpdated",         onRankUpdated);
      socket.off("signal",              onSignal);
      socket.off("videoCallDeclined",   onVideoCallDeclined);
    };
  }, [connected, myUserId]); // eslint-disable-line

  useEffect(() => {
    msgEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, partnerTyping]);

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
      setCallState("active");
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
      setCallState("calling");
      toast.success(`Calling ${partnerUsername || "partner"}… waiting for them to accept.`);
    } catch (err) { toast.error("Camera/mic: " + err.message); }
  }, [partnerUsername]); // eslint-disable-line

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

  const acceptCall = useCallback(async () => {
    const socket = socketRef.current;
    const sdp    = incomingCall?.sdp;
    if (!socket || !sdp) return;
    setIncomingCall(null);
    await startVideoReceiver(sdp, socket);
  }, [incomingCall]); // eslint-disable-line

  const declineCall = useCallback(() => {
    const socket = socketRef.current;
    setIncomingCall(null);
    setCallState("idle");
    socket?.emit("signal", { data: { declined: true } });
    toast.notif("You declined the video call.");
  }, []); // eslint-disable-line

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
    findChat();
  }, [findChat, stopVideo, resetSession]);

  const endChat = useCallback(() => {
    const pid = partnerIdRef.current;
    if (socketRef.current && pid) socketRef.current.emit("leaveChat", { partnerId: pid });
    if (chatStatus === "waiting_accept" && friendId && !accepted) cancelDirectChatRequest(friendId);
    stopVideo();
    navigate("/dashboard");
  }, [navigate, stopVideo, chatStatus, friendId, accepted, cancelDirectChatRequest]);

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

  const handleFollow = useCallback(() => {
    const socket = socketRef.current;
    const pid    = partnerIdRef.current;
    if (!socket || !pid || pid === myUserId) return;
    socket.emit("follow");
    setFollowed((p) => !p);
  }, [myUserId]);

  // Keyboard Shortcuts Hook
  useEffect(() => {
    const handleKeyDown = (e) => {
      // Ignore if typing inside messaging input bars
      if (document.activeElement?.tagName === "INPUT" || document.activeElement?.tagName === "TEXTAREA") {
        return;
      }
      
      const key = e.key.toLowerCase();
      if (key === "c") {
        e.preventDefault();
        toggleCam();
        toast.success(!camOn ? "Camera Activated" : "Camera Deactivated");
      } else if (key === "m") {
        e.preventDefault();
        toggleMic();
        toast.success(!micOn ? "Microphone Unmuted" : "Microphone Muted");
      } else if (key === "n") {
        e.preventDefault();
        if (chatStatusRef.current === "chatting") {
          skipChat();
          toast.notif("Skipping partner…");
        } else if (chatStatusRef.current === "idle" || chatStatusRef.current === "partner_left") {
          findChat();
          toast.notif("Finding new partner…");
        }
      } else if (e.key === "Escape") {
        e.preventDefault();
        endChat();
        toast.notif("Returning to Dashboard");
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [toggleCam, toggleMic, skipChat, findChat, endChat, camOn, micOn]);

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

  const partnerInitial = partnerUsername?.[0]?.toUpperCase() || "?";
  const partnerDisplay = partnerUsername || (partnerId ? `User#${partnerId.slice(-4)}` : "");

  const badge = (() => {
    if (!connected)                      return { text: "Connecting…",            color: "text-amber-400" };
    if (chatStatus === "idle")           return { text: "Ready",                  color: "text-white/40"   };
    if (chatStatus === "waiting_accept") return { text: "Pending accept…",        color: "text-blue-400 font-semibold animate-pulse"   };
    if (chatStatus === "searching")      return accepted
      ? { text: "Connecting…",   color: "text-emerald-400 animate-pulse font-semibold" }
      : { text: "Matching…",     color: "text-amber-400 animate-pulse font-semibold" };
    if (chatStatus === "chatting")       return { text: `Active Match · ${matchType || ""}`, color: "text-emerald-400 font-semibold" };
    if (chatStatus === "partner_left")   return { text: "Left chat",              color: "text-rose-400 font-semibold"    };
    return { text: "", color: "" };
  })();

  const sendRequest = useCallback(() => {
    if (!friendId) return;
    const r = sendDirectChatRequest(friendId, friendName);
    if (r) setChatStatus("waiting_accept");
  }, [friendId, friendName, sendDirectChatRequest]);

  return (
    <div
      className="h-screen flex flex-col text-white antialiased overflow-hidden transition-colors duration-700 relative"
      style={{ backgroundColor: bgFlash ? "#4c0519" : "#030303" }}
    >
      {/* Glow elements */}
      {!bgFlash && (
        <>
          <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] rounded-full bg-blue-500/5 blur-[120px] pointer-events-none pulse-glow-bg" />
          <div className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] rounded-full bg-rose-500/5 blur-[120px] pointer-events-none pulse-glow-bg" style={{ animationDelay: "-3s" }} />
        </>
      )}

      {/* HEADER */}
      <header className="flex-shrink-0 border-b border-white/5 bg-black/30 backdrop-blur-md z-30">
        <div className="px-6 py-4 flex items-center justify-between gap-4 flex-wrap">
          {/* Left info status block */}
          <div className="flex items-center gap-3.5 min-w-0">
            <button
              onClick={endChat}
              className="h-9 w-9 flex-shrink-0 flex items-center justify-center rounded-xl bg-white/5 border border-white/10 text-white/80 hover:bg-white/10 hover:text-white transition-all"
            >
              <FaArrowLeft size={12} />
            </button>
            <div className="min-w-0">
              <span className="font-bold tracking-tight text-sm text-white/90">Hangout Lobby</span>
              <div className="flex items-center gap-1.5 mt-0.5">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
                <span className={`text-[10px] tracking-wide uppercase font-semibold ${badge.color}`}>{badge.text}</span>
              </div>
            </div>
          </div>

          {/* Right action control drawer */}
          <div className="flex items-center gap-2.5 flex-wrap justify-end">
            <button
              onClick={handleSaveChat}
              disabled={saving || chatStatus !== "chatting"}
              className="glass-btn px-4 py-2 rounded-full text-xs font-semibold hover:border-white transition-all disabled:opacity-30 disabled:pointer-events-none flex items-center gap-1.5"
            >
              <FaSave size={11} className="text-white/60" />
              <span>{saving ? "Saving…" : "Save chat"}</span>
            </button>

            {chatStatus === "idle" && (
              <button
                onClick={friendId ? sendRequest : findChat}
                disabled={!connected}
                className="glass-btn-primary px-5 py-2 rounded-full text-xs font-bold disabled:opacity-30"
              >
                {friendId ? `Connect with ${friendName || "Friend"}` : "Find Match"}
              </button>
            )}

            {chatStatus === "searching" && !accepted && (
              <button onClick={cancelWaiting}
                className="px-4 py-2 rounded-full border border-amber-500/30 text-amber-300 bg-amber-500/5 text-xs font-bold hover:border-amber-400 transition-all">
                Cancel matchmaking
              </button>
            )}

            {chatStatus === "waiting_accept" && (
              <button onClick={cancelDirectRequest}
                className="px-4 py-2 rounded-full border border-rose-500/30 text-rose-300 bg-rose-500/5 text-xs font-bold hover:border-rose-400 transition-all">
                Cancel Invite
              </button>
            )}

            {chatStatus === "chatting" && (
              <button onClick={skipChat}
                className="glass-btn px-4 py-2 rounded-full text-xs font-bold hover:border-white flex items-center gap-1.5 shadow-lg">
                <span>Next Partner</span>
                <kbd className="text-[9px] bg-white/10 px-1 py-0.5 rounded border border-white/5 text-white/50 font-mono">N</kbd>
              </button>
            )}

            {chatStatus === "partner_left" && (
              <button onClick={friendId ? sendRequest : findChat}
                className="glass-btn-primary px-5 py-2 rounded-full text-xs font-bold">
                {friendId ? "Re-invite friend" : "Find Next Match"}
              </button>
            )}

            <button
              onClick={() => setMode((m) => m === "video" ? "chat" : "video")}
              className="glass-btn px-4 py-2 rounded-full text-xs font-semibold hover:border-white transition-all"
            >
              {mode === "video" ? "Hide Camera" : "Video Mode"}
            </button>
          </div>
        </div>
      </header>

      {/* MAIN CONTAINER */}
      <main className="flex-1 min-h-0 px-4 sm:px-6 py-5 flex flex-col lg:flex-row gap-5 overflow-hidden max-w-7xl mx-auto w-full z-10">

        {/* VIDEO PANEL */}
        {mode === "video" && (
          <section className="flex-1 min-w-0 min-h-0 flex flex-col glass-panel rounded-3xl overflow-hidden p-5 gap-4">

            {/* Video header details */}
            <div className="flex-shrink-0 flex items-center justify-between gap-3 border-b border-white/5 pb-4">
              <div className="flex items-center gap-3.5 min-w-0">
                <div className="h-10 w-10 flex-shrink-0 rounded-xl bg-white text-black flex items-center justify-center text-sm font-black shadow-[0_4px_12px_rgba(255,255,255,0.15)]">
                  {chatStatus === "chatting" ? partnerInitial
                    : chatStatus === "waiting_accept" ? (friendName?.[0]?.toUpperCase() || "?")
                    : "–"}
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <span className="font-bold text-sm text-white/90 truncate leading-tight">
                      {chatStatus === "chatting"        ? partnerDisplay
                        : chatStatus === "waiting_accept"   ? `Connecting ${friendName || "Friend"}`
                        : chatStatus === "searching" && accepted ? `Setup Room with ${friendName || "Friend"}…`
                        : chatStatus === "searching"            ? "Matchmaking Queue"
                        : chatStatus === "partner_left"         ? "Partner Disconnected"
                        : friendId ? `Connect with ${friendName || "Friend"}` : "Start Chatting"}
                    </span>
                    {chatStatus === "chatting" && (
                      <button
                        onClick={handleFollow}
                        className={`flex-shrink-0 px-3 py-1 rounded-full border text-[10px] font-bold tracking-wide uppercase transition-all ${
                          followed ? "bg-white text-black border-white" : "border-white/20 text-white/60 hover:text-white hover:border-white"
                        }`}
                      >
                        {followed ? "Following ✓" : "Follow"}
                      </button>
                    )}
                  </div>
                  <p className="text-[10px] text-white/40 mt-1 truncate">
                    {chatStatus === "chatting"
                      ? commonInterests.length > 0
                        ? `Shared Interests: ${commonInterests.map((i) => `#${i}`).join(" ")}`
                        : matchType === "direct" ? "Private chat session"
                        : `Matched via ${matchType ?? "random"}`
                      : chatStatus === "waiting_accept"              ? "Waiting for partner to accept invitation…"
                      : chatStatus === "searching" && accepted       ? "Initiating web socket connection…"
                      : chatStatus === "searching"                   ? "Filtering other users by common interest tags…"
                      : chatStatus === "partner_left"                ? "Your chat companion has disconnected."
                      : friendId ? "Send a direct invitation request to begin." : "Click GO below to start matching instantly."}
                  </p>
                </div>
              </div>
              {/* Leaderboard Rank score bubble */}
              <div className="flex-shrink-0 text-right bg-white/5 border border-white/10 px-3 py-1.5 rounded-2xl">
                <div className="text-[9px] font-bold text-white/40 uppercase tracking-widest leading-none">Your Rank</div>
                <div className="text-xs font-black text-amber-400 mt-1 flex items-center gap-0.5 justify-end">
                  <FaStar size={10} /> {myRank}
                </div>
              </div>
            </div>

            {/* Video stream container element */}
            <div className="flex-1 min-h-0 flex flex-col">
              <div className="relative flex-1 min-h-0 rounded-2xl bg-white/[0.02] border border-white/5 overflow-hidden flex items-center justify-center">
                {/* Ambient glow accent overlay */}
                <div className="absolute inset-0 pointer-events-none opacity-20 bg-[radial-gradient(circle_at_15%_15%,rgba(255,255,255,0.4),transparent_55%)]" />

                {/* Main Remote companion stream */}
                <video
                  ref={remoteVideoRef} autoPlay playsInline
                  className={`absolute inset-0 w-full h-full object-cover transition-opacity duration-300 ${videoActive ? "block opacity-100" : "hidden opacity-0"}`}
                />

                {/* State-driven descriptive placeholders */}
                {!videoActive && (
                  <div className="relative z-10 flex flex-col items-center gap-4 px-6 text-center max-w-sm">
                    {chatStatus === "searching" && !accepted && (
                      <>
                        <div className="h-9 w-9 rounded-full border border-white/20 border-t-white animate-spin" />
                        <p className="text-xs text-white/50 leading-relaxed">Finding your match… looking for online matches matching interests.</p>
                      </>
                    )}
                    {chatStatus === "searching" && accepted && (
                      <>
                        <div className="h-9 w-9 rounded-full border border-emerald-500/20 border-t-emerald-400 animate-spin" />
                        <p className="text-xs text-emerald-300 font-medium">Connecting to {friendName || "Friend"}…</p>
                        <p className="text-[10px] text-white/30">Preparing video call handshake negotiation.</p>
                      </>
                    )}
                    {chatStatus === "waiting_accept" && (
                      <>
                        <div className="h-9 w-9 rounded-full border border-blue-500/20 border-t-blue-400 animate-spin" />
                        <p className="text-xs text-blue-300 font-medium">Awaiting acceptance from {friendName || "friend"}…</p>
                        <p className="text-[10px] text-white/30 mb-3">They will see an invitation notification inside their dashboard.</p>
                        <button onClick={cancelDirectRequest}
                          className="glass-btn px-4 py-2 rounded-full text-[10px] font-bold text-rose-300 border-rose-500/20 hover:border-rose-500">
                          Cancel Invitation
                        </button>
                      </>
                    )}
                    {chatStatus === "chatting" && callState === "calling" && (
                      <>
                        <div className="h-[36px] w-[36px] rounded-full border border-emerald-500/20 border-t-emerald-400 animate-spin" />
                        <p className="text-xs text-emerald-300 font-medium">Calling {partnerDisplay || "partner"}…</p>
                        <p className="text-[10px] text-white/30">Waiting for companion consent to enable video stream.</p>
                      </>
                    )}
                    {chatStatus === "chatting" && callState !== "calling" && callState !== "incoming" && (
                      <>
                        <p className="text-xs text-white/30 leading-relaxed mb-1">
                          Camera video feed remains deactivated until call is initiated.
                        </p>
                        <button onClick={startVideo}
                          className="glass-btn-primary px-6 py-2.5 rounded-full text-xs font-bold flex items-center gap-1.5 shadow-lg">
                          <FaVideo size={11} /> Start Video Call
                        </button>
                      </>
                    )}
                    {chatStatus === "partner_left" && (
                      <div className="flex flex-col items-center gap-3">
                        <p className="text-xs text-white/40">Companion left the session.</p>
                        <button onClick={friendId ? sendRequest : findChat}
                          className="glass-btn-primary px-5 py-2.5 rounded-full text-xs font-bold">
                          {friendId ? "Request Again" : "Find Next Match"}
                        </button>
                      </div>
                    )}
                    {chatStatus === "idle" && (
                      <button
                        onClick={friendId ? sendRequest : findChat}
                        disabled={!connected}
                        className="w-20 h-20 rounded-2xl bg-white text-black text-lg font-black hover:scale-105 hover:rounded-3xl transition-all shadow-[0_8px_32px_rgba(255,255,255,0.15)] disabled:opacity-30 flex items-center justify-center"
                      >
                        {friendId ? "CHAT" : "GO"}
                      </button>
                    )}
                  </div>
                )}

                {/* Hang up call action */}
                {videoActive && (
                  <button onClick={stopVideo}
                    className="absolute top-4 right-4 z-20 px-4 py-2 rounded-full bg-rose-600/90 text-white text-xs font-bold hover:bg-rose-600 hover:scale-105 transition-all flex items-center gap-1 shadow-lg">
                    <IoIosCloseCircle size={14} /> End Stream
                  </button>
                )}

                {/* INCOMING CALL OVERLAY */}
                {callState === "incoming" && incomingCall && (
                  <div className="absolute inset-0 z-30 flex flex-col items-center justify-center bg-black/90 backdrop-blur-md">
                    <div className="relative mb-6">
                      <div className="absolute inset-0 rounded-2xl bg-emerald-500/10 animate-ping" style={{ animationDuration: "1.5s" }} />
                      <div className="absolute inset-[-6px] rounded-2xl border border-emerald-400/20 animate-pulse" />
                      <div className="relative h-20 w-20 rounded-2xl bg-white text-black flex items-center justify-center text-3xl font-black shadow-[0_0_40px_rgba(16,185,129,0.25)]">
                        {partnerInitial}
                      </div>
                    </div>

                    <p className="text-base font-bold text-white mb-0.5">{partnerDisplay || "Companion"}</p>
                    <p className="text-xs text-emerald-400 font-semibold mb-1 tracking-wide animate-pulse">Incoming video call proposal…</p>
                    <p className="text-[10px] text-white/30 mb-6 text-center px-6">Consent: Your local camera &amp; mic will activate if you choose to accept.</p>

                    <div className="flex items-center gap-6">
                      <button
                        onClick={acceptCall}
                        className="flex flex-col items-center gap-2 group"
                      >
                        <div className="h-14 w-14 rounded-full bg-emerald-500 flex items-center justify-center text-white text-xl hover:bg-emerald-400 hover:scale-105 transition-all shadow-[0_6px_20px_rgba(16,185,129,0.3)]">
                          <FaVideo size={18} />
                        </div>
                        <span className="text-[10px] font-bold text-emerald-400 group-hover:text-emerald-300 uppercase tracking-wider">Accept</span>
                      </button>
                      <button
                        onClick={declineCall}
                        className="flex flex-col items-center gap-2 group"
                      >
                        <div className="h-14 w-14 rounded-full bg-rose-500 flex items-center justify-center text-white text-lg hover:bg-rose-400 hover:scale-105 transition-all shadow-[0_6px_20px_rgba(244,63,94,0.3)]">
                          <FaTimes size={15} />
                        </div>
                        <span className="text-[10px] font-bold text-rose-400 group-hover:text-rose-300 uppercase tracking-wider">Decline</span>
                      </button>
                    </div>
                  </div>
                )}

                {/* Picture in picture Local stream preview window */}
                <div className={`absolute bottom-4 right-4 z-10 w-32 h-24 rounded-xl border border-white/10 overflow-hidden bg-black/60 backdrop-blur-md flex items-center justify-center shadow-lg transition-transform ${!videoActive ? "hidden" : "hover:scale-105"}`}>
                  <video ref={localVideoRef} autoPlay muted playsInline
                    className={`w-full h-full object-cover ${camOn ? "block" : "hidden"}`} />
                  {!camOn && <span className="text-[10px] font-semibold text-white/30">Camera Disabled</span>}
                </div>
              </div>

              {/* Video control bottom bar row */}
              <div className="flex-shrink-0 mt-3 flex items-center justify-between gap-3 flex-wrap">
                <div className="flex items-center gap-2">
                  <button onClick={toggleMic}
                    className={`px-4 py-2 rounded-xl border text-xs font-semibold transition-all flex items-center gap-1.5 ${
                      micOn ? "bg-white text-black border-white font-bold" : "bg-white/5 text-white/60 border-white/5"
                    }`}>
                    {micOn ? <FaMicrophone size={11} /> : <FaMicrophoneSlash size={11} />}
                    <span>{micOn ? "Mute Mic" : "Muted"}</span>
                    <kbd className={`text-[9px] px-1 py-0.5 rounded font-mono ${micOn ? "bg-black/10 text-black/55" : "bg-white/10 text-white/40"}`}>M</kbd>
                  </button>
                  <button onClick={toggleCam}
                    className={`px-4 py-2 rounded-xl border text-xs font-semibold transition-all flex items-center gap-1.5 ${
                      camOn ? "bg-white text-black border-white font-bold" : "bg-white/5 text-white/60 border-white/5"
                    }`}>
                    <FaCamera size={11} />
                    <span>{camOn ? "Disable Camera" : "Cam Off"}</span>
                    <kbd className={`text-[9px] px-1 py-0.5 rounded font-mono ${camOn ? "bg-black/10 text-black/55" : "bg-white/10 text-white/40"}`}>C</kbd>
                  </button>
                </div>
                <div className="flex items-center gap-2.5">
                  <button
                    onClick={handleLike}
                    disabled={chatStatus !== "chatting" || partnerId === myUserId}
                    title={liked ? "Remove heart contribution" : "Add heart contribution to partner!"}
                    className={`h-9 w-9 flex items-center justify-center rounded-xl border transition-all text-sm ${
                      liked ? "bg-rose-500 border-none text-white shadow-lg" : "border-white/10 bg-white/5 hover:border-white/30"
                    } disabled:opacity-30 disabled:pointer-events-none`}
                  >
                    {liked ? <FaHeart size={13} /> : <FaRegHeart size={13} className="text-white/60" />}
                  </button>
                  <button onClick={endChat}
                    className="glass-btn px-4 py-2 rounded-xl text-xs font-bold hover:border-white flex items-center gap-1.5">
                    <span>Leave lobby</span>
                    <kbd className="text-[9px] bg-white/10 px-1 py-0.5 rounded border border-white/5 text-white/50 font-mono">Esc</kbd>
                  </button>
                </div>
              </div>
            </div>
          </section>
        )}

        {/* CHAT TEXT PANEL */}
        <section className={`min-h-0 flex flex-col glass-panel rounded-3xl overflow-hidden p-5 gap-4 ${
          mode === "video" ? "w-full lg:w-80 xl:w-96 flex-shrink-0" : "flex-1"
        }`}>

          {/* Panel header details */}
          <div className="flex-shrink-0 flex items-center justify-between border-b border-white/5 pb-3.5">
            <div className="min-w-0">
              <h2 className="text-xs font-bold text-white/40 uppercase tracking-widest truncate">
                {chatStatus === "chatting" && partnerDisplay
                  ? `Companion text chat`
                  : chatStatus === "waiting_accept"
                  ? `Invite Pending`
                  : chatStatus === "searching" && accepted
                  ? `Setup room…`
                  : "Conversation"}
              </h2>
              {chatStatus === "chatting" && commonInterests.length > 0 && (
                <p className="text-[10px] text-white/40 truncate mt-1">
                  Common: {commonInterests.map((i) => `#${i}`).join(" ")}
                </p>
              )}
            </div>
            <span className={`text-[10px] font-bold ${badge.color}`}>{badge.text}</span>
          </div>

          {/* Chat message timeline list */}
          <div className="flex-1 min-h-0 overflow-y-auto space-y-3 pr-1 no-scrollbar">

            {chatStatus === "idle" && (
              <div className="h-full flex flex-col items-center justify-center gap-3.5 text-center px-4">
                <p className="text-white/30 text-xs">Ready to connect when you are. Initiate matching below.</p>
                <button
                  onClick={friendId ? sendRequest : findChat}
                  disabled={!connected}
                  className="glass-btn-primary px-6 py-2.5 rounded-full text-xs font-bold disabled:opacity-30"
                >
                  {friendId ? `Invite ${friendName || "Friend"}` : "Start Matching"}
                </button>
              </div>
            )}

            {chatStatus === "waiting_accept" && (
              <div className="h-full flex flex-col items-center justify-center gap-3 text-center px-4">
                <div className="h-6 w-6 rounded-full border border-blue-400 border-t-transparent animate-spin" />
                <p className="text-blue-300 text-xs font-semibold">Waiting for companion response…</p>
                <p className="text-white/30 text-[10px]">An invite alert will appear on their dashboard window.</p>
                <button onClick={cancelDirectRequest}
                  className="glass-btn px-4 py-2 rounded-full text-[10px] text-rose-400 font-bold border-rose-500/20 hover:border-rose-500 mt-2">
                  Cancel Invitation
                </button>
              </div>
            )}

            {chatStatus === "searching" && !accepted && (
              <div className="h-full flex flex-col items-center justify-center gap-3 text-center px-4">
                <div className="h-6 w-6 rounded-full border border-white/20 border-t-white animate-spin" />
                <p className="text-white/45 text-xs">Scanning matchmaking pool…</p>
                <button onClick={cancelWaiting}
                  className="glass-btn px-4 py-2 rounded-full text-[10px] text-amber-300 font-bold border-amber-500/20 hover:border-amber-400 mt-2">
                  Leave Queue
                </button>
              </div>
            )}

            {chatStatus === "searching" && accepted && (
              <div className="h-full flex flex-col items-center justify-center gap-3 text-center px-4">
                <div className="h-6 w-6 rounded-full border border-emerald-500/20 border-t-emerald-400 animate-spin" />
                <p className="text-emerald-300 text-xs font-semibold">Connecting to friend…</p>
                <p className="text-white/30 text-[10px]">Negotiating connection sockets.</p>
              </div>
            )}

            {chatStatus === "partner_left" && (
              <div className="h-full flex flex-col items-center justify-center gap-3.5 text-center px-4">
                <p className="text-white/30 text-xs">Companion disconnected.</p>
                <button onClick={friendId ? sendRequest : findChat}
                  className="glass-btn-primary px-5 py-2.5 rounded-full text-xs font-bold">
                  {friendId ? "Invite Again" : "Next Match"}
                </button>
              </div>
            )}

            {chatStatus === "chatting" && messages.length === 0 && (
              <div className="h-full flex flex-col items-center justify-center text-center">
                <p className="text-white/30 text-xs">Connected companion found!</p>
                <p className="text-[10px] text-emerald-400 font-bold uppercase tracking-wider mt-1.5">Say hello to start conversing</p>
              </div>
            )}

            {messages.map((msg) => (
              <div key={msg.id} className="space-y-1">
                {msg.from === "partner" && (
                  <div className="text-[9px] font-bold text-white/30 pl-2 uppercase tracking-wide">{partnerDisplay}</div>
                )}
                <div className={`flex ${msg.from === "me" ? "justify-end" : "justify-start"}`}>
                  <div className={`max-w-[80%] rounded-2xl px-3.5 py-2.5 break-words text-xs leading-relaxed ${
                    msg.from === "me"
                      ? "bg-white text-black font-medium"
                      : "bg-white/5 text-white/90 border border-white/5"
                  }`}>
                    {msg.text}
                  </div>
                </div>
                <div className={`text-[9px] text-white/30 ${
                  msg.from === "me" ? "text-right pr-2" : "pl-2"
                }`}>
                  {msg.time}
                </div>
              </div>
            ))}

            {/* Pulsing visual typing indicators */}
            {partnerTyping && chatStatus === "chatting" && (
              <div className="space-y-1">
                <div className="text-[9px] font-bold text-white/30 pl-2 uppercase tracking-wide">{partnerDisplay}</div>
                <div className="flex justify-start">
                  <div className="bg-white/5 border border-white/5 rounded-2xl px-3.5 py-2.5 flex items-center gap-1.5">
                    <span className="h-1.5 w-1.5 rounded-full bg-white/40 animate-bounce [animation-delay:0ms]" />
                    <span className="h-1.5 w-1.5 rounded-full bg-white/40 animate-bounce [animation-delay:150ms]" />
                    <span className="h-1.5 w-1.5 rounded-full bg-white/40 animate-bounce [animation-delay:300ms]" />
                  </div>
                </div>
              </div>
            )}
            <div ref={msgEndRef} />
          </div>

          {/* Form input bar */}
          <form onSubmit={handleSend} className="flex-shrink-0 mt-2 pt-3.5 border-t border-white/5">
            <div className="flex items-center gap-2">
              <input
                type="text"
                placeholder={chatStatus === "chatting" ? "Type a message…" : "Connect to chat companion"}
                value={input}
                onChange={(e) => handleInputChange(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) handleSend(e); }}
                disabled={chatStatus !== "chatting"}
                className="flex-1 min-w-0 bg-transparent border-none outline-none text-xs placeholder:text-white/20 disabled:opacity-30"
              />
              <button type="submit"
                disabled={chatStatus !== "chatting" || !input.trim()}
                className="flex-shrink-0 h-8 w-8 rounded-xl bg-white text-black hover:bg-gray-200 transition-all disabled:opacity-30 flex items-center justify-center shadow-md">
                <FaPaperPlane size={11} />
              </button>
            </div>
          </form>
        </section>
      </main>

      {/* Upload Modal (kept for functional parity) */}
      {uploadOpen && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4 backdrop-blur-md">
          <div className="bg-black/90 border border-white/10 rounded-3xl p-6 w-80 max-w-full backdrop-blur-xl space-y-4">
            <h3 className="text-xs font-bold uppercase tracking-wider text-white/40">Upload image asset</h3>
            <input
              type="file" accept="image/*"
              onChange={(e) => { if (e.target.files?.[0]) setFileName(e.target.files[0].name); }}
              className="w-full text-xs text-white/60 file:mr-3 file:py-1.5 file:px-3 file:rounded-xl file:border-0 file:bg-white file:text-black file:text-xs file:font-semibold"
            />
            {fileName && <p className="text-[10px] text-emerald-400 font-medium">{fileName}</p>}
            <div className="flex justify-end pt-2">
              <button onClick={() => { setUploadOpen(false); setFileName(""); }}
                className="glass-btn px-4 py-2 rounded-xl text-xs font-bold hover:border-white">
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
