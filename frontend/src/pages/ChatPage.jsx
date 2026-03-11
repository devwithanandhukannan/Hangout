import { useState, useRef, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { io } from "socket.io-client";
import { useAuth } from "../AuthContext";

const SOCKET_URL = "http://localhost:8000";

const RTC_CONFIG = {
  iceServers: [{ urls: "stun:stun.l.google.com:19302" }],
};

export default function ChatPage() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const myUserId = user?._id || user?.id || "";

  // ── Refs ──────────────────────────────────────────────────────────────────
  const socketRef     = useRef(null);
  const pcRef         = useRef(null);
  const localStream   = useRef(null);
  const localVideoEl  = useRef(null);
  const remoteVideoEl = useRef(null);
  const msgEndRef     = useRef(null);
  const flashTimer    = useRef(null);
  const chatDataRef   = useRef({});
  const msgIndexRef   = useRef(0);
  const roomRef       = useRef(null);
  const partnerIdRef  = useRef(null);

  // ── UI State ──────────────────────────────────────────────────────────────
  const [mode, setMode]               = useState("video");
  const [micOn, setMicOn]             = useState(true);
  const [camOn, setCamOn]             = useState(true);
  const [bgFlash, setBgFlash]         = useState(false);
  const [messages, setMessages]       = useState([]);
  const [input, setInput]             = useState("");
  const [saving, setSaving]           = useState(false);
  const [saveStatus, setSaveStatus]   = useState("");
  const [uploadOpen, setUploadOpen]   = useState(false);
  const [fileName, setFileName]       = useState("");
  const [videoCallActive, setVideoCallActive] = useState(false);
  const [socketReady, setSocketReady] = useState(false);
  const [chatStatus, setChatStatus]   = useState("idle");
  const [room, setRoom]               = useState(null);
  const [partnerId, setPartnerId]     = useState(null);
  const [matchType, setMatchType]     = useState(null);
  const [liked, setLiked]             = useState(false);
  const [followed, setFollowed]       = useState(false);

  useEffect(() => { roomRef.current = room; }, [room]);
  useEffect(() => { partnerIdRef.current = partnerId; }, [partnerId]);

  // ── Stop video call ───────────────────────────────────────────────────────
  const stopVideoCall = useCallback(() => {
    if (pcRef.current) { pcRef.current.close(); pcRef.current = null; }
    if (localStream.current) {
      localStream.current.getTracks().forEach((t) => t.stop());
      localStream.current = null;
    }
    if (localVideoEl.current)  localVideoEl.current.srcObject  = null;
    if (remoteVideoEl.current) remoteVideoEl.current.srcObject = null;
    setVideoCallActive(false);
  }, []);

  // ── Socket setup ──────────────────────────────────────────────────────────
  useEffect(() => {
    const socket = io(SOCKET_URL, {
      withCredentials: true,
      transports: ["polling", "websocket"],
    });
    socketRef.current = socket;

    socket.on("connect", () => {
      setSocketReady(true);
      socket.emit("getInterests");
    });
    socket.on("connect_error", () => setSocketReady(false));
    socket.on("disconnect", () => { setSocketReady(false); setChatStatus("idle"); });

    socket.on("waitingForPartner", () => setChatStatus("searching"));

    socket.on("chatStarted", ({ room: r, partnerId: pid, matchType: mt }) => {
      roomRef.current      = r;
      partnerIdRef.current = pid;
      setRoom(r); setPartnerId(pid); setMatchType(mt);
      setChatStatus("chatting");
      setMessages([]); setLiked(false); setFollowed(false);
      chatDataRef.current = {}; msgIndexRef.current = 0;
      stopVideoCall();
    });

    socket.on("privateMessage", ({ senderId, text }) => {
      const time = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      const idx  = msgIndexRef.current;
      chatDataRef.current[idx] = { user: "partner", message: text, time };
      msgIndexRef.current += 1;
      setMessages((prev) => [...prev, { id: Date.now() + Math.random(), from: "partner", text, senderId, time }]);
    });

    socket.on("partnerLeft",         () => { setChatStatus("partner_left"); setRoom(null); setPartnerId(null); roomRef.current = null; partnerIdRef.current = null; stopVideoCall(); });
    socket.on("partnerDisconnected", () => { setChatStatus("partner_left"); setRoom(null); setPartnerId(null); roomRef.current = null; partnerIdRef.current = null; stopVideoCall(); });

    socket.on("ranked",   ({ partnerId: pid }) => console.log("ranked:", pid));
    socket.on("followed", ({ partnerId: pid }) => { console.log("followed:", pid); setFollowed(true); });

    socket.on("signal", async ({ data }) => {
      if (!pcRef.current) return;
      try {
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
    });

    return () => { stopVideoCall(); socket.disconnect(); };
  }, []); // eslint-disable-line

  useEffect(() => { msgEndRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages]);

  // ── Start video call ──────────────────────────────────────────────────────
  const startVideoCall = useCallback(async () => {
    if (!socketRef.current || !roomRef.current) return;
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
      localStream.current = stream;
      if (localVideoEl.current) localVideoEl.current.srcObject = stream;

      const pc = new RTCPeerConnection(RTC_CONFIG);
      pcRef.current = pc;
      stream.getTracks().forEach((t) => pc.addTrack(t, stream));
      pc.ontrack = (e) => { if (remoteVideoEl.current) remoteVideoEl.current.srcObject = e.streams[0]; };
      pc.onicecandidate = (e) => {
        if (e.candidate) socketRef.current.emit("signal", { data: { candidate: e.candidate } });
      };

      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      socketRef.current.emit("signal", { data: { sdp: offer } });

      setVideoCallActive(true);
      stream.getAudioTracks().forEach((t) => { t.enabled = micOn; });
      stream.getVideoTracks().forEach((t) => { t.enabled = camOn; });
    } catch (err) {
      alert("Could not access camera/mic: " + err.message);
    }
  }, [micOn, camOn]);

  // ── Actions ───────────────────────────────────────────────────────────────
  const findChat = useCallback(() => {
    if (!socketRef.current?.connected) return;
    setChatStatus("searching");
    setMessages([]); setRoom(null); setPartnerId(null);
    chatDataRef.current = {}; msgIndexRef.current = 0;
    socketRef.current.emit("findChat");
  }, []);

  const skipChat = useCallback(() => {
    const pid = partnerIdRef.current;
    if (socketRef.current && pid) socketRef.current.emit("leaveChat", { partnerId: pid });
    stopVideoCall();
    setRoom(null); setPartnerId(null); setMessages([]);
    findChat();
  }, [findChat, stopVideoCall]);

  const endChat = useCallback(() => {
    const pid = partnerIdRef.current;
    if (socketRef.current && pid) socketRef.current.emit("leaveChat", { partnerId: pid });
    stopVideoCall();
    navigate("/dashboard");
  }, [navigate, stopVideoCall]);

  const handleSend = useCallback((e) => {
    e?.preventDefault();
    const text = input.trim();
    if (!text || !roomRef.current || !socketRef.current) return;
    const time = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    const idx  = msgIndexRef.current;
    chatDataRef.current[idx] = { user: "me", message: text, time };
    msgIndexRef.current += 1;
    setMessages((prev) => [...prev, { id: Date.now(), from: "me", text, senderId: myUserId, time }]);
    socketRef.current.emit("privateMessage", { text, room: roomRef.current });
    setInput("");
  }, [input, myUserId]);

  const handleLike = useCallback(() => {
    if (!roomRef.current || !socketRef.current) return;
    if (partnerIdRef.current === myUserId) return;
    socketRef.current.emit("like");
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
    if (!roomRef.current || !socketRef.current) return;
    if (partnerIdRef.current === myUserId) return;
    socketRef.current.emit("follow");
    setFollowed((prev) => !prev);
  }, [myUserId]);

  const handleSaveChat = useCallback(async () => {
    const pid = partnerIdRef.current;
    if (!pid) { setSaveStatus("No partner."); setTimeout(() => setSaveStatus(""), 2000); return; }
    const chatData = chatDataRef.current;
    if (Object.keys(chatData).length === 0) { setSaveStatus("Nothing to save."); setTimeout(() => setSaveStatus(""), 2000); return; }
    setSaving(true);
    try {
      const res = await fetch(`${SOCKET_URL}/save-chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ partnerId: pid, chatData }),
      });
      const data = await res.json();
      setSaveStatus(data.success ? "Saved!" : data.message || "Failed");
    } catch { setSaveStatus("Failed"); }
    finally { setSaving(false); setTimeout(() => setSaveStatus(""), 3000); }
  }, []);

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

  // ── Status badge ──────────────────────────────────────────────────────────
  const badge = (() => {
    if (!socketReady)                  return { text: "Connecting…",          color: "text-yellow-400" };
    if (chatStatus === "idle")         return { text: "Ready",                color: "text-gray-400"   };
    if (chatStatus === "searching")    return { text: "Searching…",           color: "text-yellow-400" };
    if (chatStatus === "chatting")     return { text: `Connected · ${matchType || ""}`, color: "text-green-400" };
    if (chatStatus === "partner_left") return { text: "Partner left",         color: "text-red-400"    };
    return { text: "", color: "" };
  })();

  // ─────────────────────────────────────────────────────────────────────────
  return (
    <div
      className="h-screen flex flex-col text-white antialiased transition-colors duration-500 overflow-hidden"
      style={{ backgroundColor: bgFlash ? "#330000" : "#000000" }}
    >
      {/* ── Header ────────────────────────────────────────────────────────── */}
      <header className="flex-shrink-0 border-b border-white/10 bg-black/40 backdrop-blur">
        <div className="px-4 sm:px-6 py-3 flex items-center justify-between gap-2">
          {/* Left */}
          <div className="flex items-center gap-2 min-w-0">
            <button
              onClick={endChat}
              className="h-8 w-8 flex-shrink-0 flex items-center justify-center rounded-full border border-white/40 text-sm hover:bg-white hover:text-black transition"
            >←</button>
            <span className="font-semibold text-sm whitespace-nowrap">Hangout</span>
            <span className={`text-[11px] truncate ${badge.color}`}>{badge.text}</span>
          </div>

          {/* Right */}
          <div className="flex items-center gap-1.5 flex-wrap justify-end">
            {saveStatus && <span className="text-[11px] text-green-400">{saveStatus}</span>}

            <button
              onClick={handleSaveChat}
              disabled={saving || chatStatus !== "chatting"}
              className="px-3 py-1 rounded-full border border-white text-xs hover:bg-white hover:text-black transition disabled:opacity-40"
            >{saving ? "Saving…" : "Save chat"}</button>

            {chatStatus === "idle" && (
              <button onClick={findChat} disabled={!socketReady}
                className="px-3 py-1 rounded-full border border-white text-xs hover:bg-white hover:text-black transition disabled:opacity-40">
                Find match
              </button>
            )}
            {chatStatus === "chatting" && (
              <button onClick={skipChat}
                className="px-3 py-1 rounded-full border border-white text-xs hover:bg-white hover:text-black transition">
                Skip
              </button>
            )}
            {chatStatus === "partner_left" && (
              <button onClick={findChat}
                className="px-3 py-1 rounded-full border border-white text-xs hover:bg-white hover:text-black transition">
                Find new match
              </button>
            )}

            <button
              onClick={() => setMode((m) => (m === "video" ? "chat" : "video"))}
              className="px-3 py-1 rounded-full border border-white text-xs hover:bg-white hover:text-black transition"
            >{mode === "video" ? "Text only" : "Video mode"}</button>
          </div>
        </div>
      </header>

      {/* ── Main ──────────────────────────────────────────────────────────── */}
      <main className="flex-1 min-h-0 px-4 sm:px-6 py-4 flex flex-col lg:flex-row gap-4 overflow-hidden">

        {/* ══ VIDEO PANEL ══════════════════════════════════════════════════ */}
        {mode === "video" && (
          <section className="flex-1 min-h-0 min-w-0 flex flex-col bg-white/5 border border-white/15 rounded-3xl backdrop-blur-xl overflow-hidden px-4 sm:px-6 py-4">

            {/* Partner header */}
            <div className="flex-shrink-0 flex items-center justify-between">
              <div className="flex items-center gap-3 min-w-0">
                <div className="h-10 w-10 flex-shrink-0 rounded-full bg-white text-black flex items-center justify-center text-sm font-semibold">
                  {chatStatus === "chatting" ? "?" : "…"}
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-semibold text-sm truncate">
                      {chatStatus === "chatting"
                        ? `Partner #${partnerId?.slice(-4) ?? "????"}`
                        : chatStatus === "searching"   ? "Searching…"
                        : chatStatus === "partner_left"? "Partner left"
                        : "Start a chat"}
                    </span>
                    {chatStatus === "chatting" && (
                      <button onClick={handleFollow}
                        className={`px-2 py-0.5 rounded-full border text-[11px] transition flex-shrink-0 ${
                          followed ? "bg-white text-black border-white" : "border-white hover:bg-white hover:text-black"
                        }`}>
                        {followed ? "Following ✓" : "Follow"}
                      </button>
                    )}
                  </div>
                  <p className="text-[11px] text-gray-400 mt-0.5 truncate">
                    {chatStatus === "chatting"     ? `Matched via ${matchType ?? "interest"}`
                    : chatStatus === "searching"   ? "Looking for someone with your interests…"
                    : chatStatus === "partner_left"? "Your partner disconnected."
                    : "Click 'Find match' to get started."}
                  </p>
                </div>
              </div>
            </div>

            {/* Video area — fills remaining height */}
            <div className="flex-1 min-h-0 mt-4 flex flex-col">

              {/* Video box */}
              <div className="relative flex-1 min-h-0 rounded-2xl bg-white/10 border border-white/20 overflow-hidden flex items-center justify-center">
                <div className="absolute inset-0 opacity-30 bg-[radial-gradient(circle_at_10%_10%,rgba(255,255,255,0.4),transparent_55%)] pointer-events-none" />

                {/* Remote video */}
                <video ref={remoteVideoEl} autoPlay playsInline
                  className={`absolute inset-0 w-full h-full object-cover ${videoCallActive ? "block" : "hidden"}`} />

                {/* Placeholder when no video */}
                {!videoCallActive && (
                  <div className="relative z-10 flex flex-col items-center gap-4 text-center px-6">
                    {chatStatus === "searching" ? (
                      <>
                        <div className="h-10 w-10 rounded-full border-2 border-white border-t-transparent animate-spin" />
                        <span className="text-sm text-gray-300">Finding your match…</span>
                      </>
                    ) : chatStatus === "chatting" ? (
                      <>
                        <p className="text-xs text-gray-400">Their camera appears here when video starts.</p>
                        <button onClick={startVideoCall}
                          className="px-6 py-2.5 rounded-full bg-white text-black text-sm font-semibold hover:bg-gray-200 transition">
                          📹 Start Video Call
                        </button>
                      </>
                    ) : chatStatus === "partner_left" ? (
                      <div className="flex flex-col items-center gap-3">
                        <p className="text-sm text-gray-300">Partner left the chat.</p>
                        <button onClick={findChat} className="px-5 py-2 rounded-full bg-white text-black text-xs font-semibold hover:bg-gray-200 transition">
                          Find new match
                        </button>
                      </div>
                    ) : (
                      <button onClick={findChat} disabled={!socketReady}
                        className="w-24 h-24 rounded-full bg-white text-black text-2xl font-bold hover:scale-105 transition-transform shadow-[0_0_40px_rgba(255,255,255,0.25)] disabled:opacity-40">
                        GO
                      </button>
                    )}
                  </div>
                )}

                {/* End call overlay button */}
                {videoCallActive && (
                  <button onClick={stopVideoCall}
                    className="absolute top-3 right-3 z-20 px-3 py-1 rounded-full bg-red-600 text-white text-xs hover:bg-red-700 transition">
                    End Call
                  </button>
                )}

                {/* Local preview pip */}
                <div className={`absolute bottom-3 right-3 z-10 w-32 h-24 rounded-xl border border-white/20 overflow-hidden bg-black flex items-center justify-center ${!videoCallActive ? "hidden" : ""}`}>
                  <video ref={localVideoEl} autoPlay muted playsInline
                    className={`w-full h-full object-cover ${camOn ? "block" : "hidden"}`} />
                  {!camOn && <span className="text-[11px] text-gray-400">Camera off</span>}
                </div>
              </div>

              {/* Controls */}
              <div className="flex-shrink-0 mt-3 flex items-center justify-between gap-3">
                <div className="flex items-center gap-2 text-xs flex-wrap">
                  <button onClick={toggleMic}
                    className={`px-3 py-1.5 rounded-full border flex items-center gap-1.5 transition ${micOn ? "bg-white text-black border-white" : "bg-white/10 text-white border-white/30"}`}>
                    <span>🎙</span><span>{micOn ? "Mic on" : "Muted"}</span>
                  </button>
                  <button onClick={toggleCam}
                    className={`px-3 py-1.5 rounded-full border flex items-center gap-1.5 transition ${camOn ? "bg-white text-black border-white" : "bg-white/10 text-white border-white/30"}`}>
                    <span>📹</span><span>{camOn ? "Cam on" : "Cam off"}</span>
                  </button>
                </div>

                <div className="flex items-center gap-2">
                  <button onClick={handleLike}
                    disabled={chatStatus !== "chatting" || partnerId === myUserId}
                    title={liked ? "Unlike" : "Like"}
                    className={`h-9 w-9 flex items-center justify-center rounded-full border transition text-sm ${
                      liked ? "bg-red-500 border-red-400 text-white" : "border-gray-400 hover:bg-white hover:text-black"
                    } disabled:opacity-40`}>
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

        {/* ══ CHAT PANEL ═══════════════════════════════════════════════════ */}
        <section className={`min-h-0 flex flex-col bg-white/5 border border-white/15 rounded-3xl backdrop-blur-xl overflow-hidden px-4 sm:px-5 py-4 ${
          mode === "video" ? "w-full lg:w-80 xl:w-96" : "flex-1"
        }`}>
          {/* Header */}
          <div className="flex-shrink-0 flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold">Text chat</h2>
            <span className={`text-[10px] ${badge.color}`}>{badge.text}</span>
          </div>

          {/* Messages */}
          <div className="flex-1 min-h-0 overflow-y-auto space-y-2 pr-1">
            {chatStatus === "idle" && (
              <div className="h-full flex flex-col items-center justify-center gap-4 text-center">
                <p className="text-gray-500 text-xs">Not connected yet.</p>
                <button onClick={findChat} disabled={!socketReady}
                  className="px-6 py-2.5 rounded-full bg-white text-black text-xs font-semibold hover:bg-gray-200 disabled:opacity-40 transition">
                  Find match
                </button>
              </div>
            )}
            {chatStatus === "searching" && (
              <div className="h-full flex flex-col items-center justify-center gap-3 text-center">
                <div className="h-7 w-7 rounded-full border-2 border-white border-t-transparent animate-spin" />
                <p className="text-gray-400 text-xs">Searching for someone with your interests…</p>
              </div>
            )}
            {chatStatus === "partner_left" && (
              <div className="h-full flex flex-col items-center justify-center gap-3 text-center">
                <p className="text-gray-400 text-xs">Partner left.</p>
                <button onClick={findChat} className="text-white underline text-xs">Find new match</button>
              </div>
            )}
            {chatStatus === "chatting" && messages.length === 0 && (
              <div className="h-full flex items-center justify-center">
                <p className="text-gray-500 text-xs">Connected! Say hello 👋</p>
              </div>
            )}

            {messages.map((msg) => (
              <div key={msg.id}>
                <div className={`flex ${msg.from === "me" ? "justify-end" : "justify-start"}`}>
                  <div className={`max-w-[78%] rounded-2xl px-3 py-2 break-words text-sm leading-relaxed ${
                    msg.from === "me" ? "bg-white text-black" : "bg-gray-900 text-white border border-white/10"
                  }`}>
                    {msg.text}
                  </div>
                </div>
                <div className={`text-[10px] text-gray-500 mt-0.5 ${msg.from === "me" ? "text-right pr-1" : "pl-1"}`}>
                  {msg.time}
                </div>
              </div>
            ))}
            <div ref={msgEndRef} />
          </div>

          {/* Input */}
          <form onSubmit={handleSend} className="flex-shrink-0 mt-3 pt-3 border-t border-white/10">
            <div className="flex items-center gap-2">
              <button type="button" onClick={() => setUploadOpen(true)}
                className="h-8 w-8 flex-shrink-0 flex items-center justify-center rounded-full border border-gray-700 hover:bg-gray-900 text-lg">
                +
              </button>
              <input type="text"
                placeholder={chatStatus === "chatting" ? "Type a message…" : "Connect to chat"}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                disabled={chatStatus !== "chatting"}
                className="flex-1 min-w-0 bg-transparent border-none outline-none text-sm placeholder:text-gray-500 disabled:opacity-40"
              />
              <button type="submit" disabled={chatStatus !== "chatting" || !input.trim()}
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
            <input type="file" accept="image/*"
              onChange={(e) => { if (e.target.files?.[0]) setFileName(e.target.files[0].name); }}
              className="w-full text-xs text-gray-300 file:mr-3 file:py-1.5 file:px-3 file:rounded-full file:border-0 file:bg-white file:text-black file:text-xs" />
            {fileName && <p className="mt-2 text-[11px] text-gray-400">{fileName}</p>}
            <div className="mt-4 flex justify-end gap-2 text-xs">
              <button onClick={() => { setUploadOpen(false); setFileName(""); }}
                className="px-3 py-1 rounded-full border border-gray-600 hover:bg-gray-900 transition">
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
