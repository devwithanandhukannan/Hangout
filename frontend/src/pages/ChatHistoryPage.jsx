import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { getChats, deleteChat } from "../api";
import { useAuth } from "../AuthContext";
import { 
  FaHome, FaHistory, FaStar, FaTrashAlt, FaFolderOpen, 
  FaComments, FaChevronLeft, FaSearch 
} from "react-icons/fa";
import { CgCommunity } from "react-icons/cg";
import { IoIosAddCircle, IoIosSettings } from "react-icons/io";

function normalizeMessages(rawMessages, myId) {
  if (!rawMessages) return [];
  if (!Array.isArray(rawMessages) && typeof rawMessages === "object") {
    return Object.values(rawMessages).map((m) => ({
      from: m.user === "me" ? "me" : "partner",
      text: m.message || m.text || "",
      time: m.time || "",
    }));
  }
  if (Array.isArray(rawMessages)) {
    return rawMessages.map((m) => {
      const senderId = typeof m.senderId === "object" ? m.senderId?._id || m.senderId?.id : m.senderId;
      const isMe = senderId?.toString() === myId?.toString();
      return {
        from: isMe ? "me" : "partner",
        text: m.text || m.message || "",
        time: m.time || "",
        senderId,
      };
    });
  }
  return [];
}

function getPartnerInfo(chat, myId) {
  if (!chat?.users) return { name: "Unknown", initial: "?" };
  const partner = chat.users.find((u) => {
    const uid = typeof u === "string" ? u : u?._id || u?.id;
    return uid?.toString() !== myId?.toString();
  });
  if (!partner) return { name: "Unknown", initial: "?" };
  const name =
    typeof partner === "object"
      ? partner.username || `User#${(partner._id || partner.id)?.toString().slice(-4)}`
      : `User#${partner.slice(-4)}`;
  return { name, initial: name[0]?.toUpperCase() || "?" };
}

function formatDate(dateStr) {
  if (!dateStr) return "";
  const d = new Date(dateStr);
  const diff = Date.now() - d;
  const days = Math.floor(diff / 86400000);
  if (days === 0) return "Today";
  if (days === 1) return "Yesterday";
  if (days < 7) return `${days} days ago`;
  return d.toLocaleDateString();
}

export default function ChatHistoryPage() {
  const { user } = useAuth();
  const [chats, setChats]               = useState([]);
  const [selectedChat, setSelectedChat] = useState(null);
  const [loading, setLoading]           = useState(true);
  const [error, setError]               = useState("");
  const [searchFilter, setSearchFilter] = useState("");
  const [deleting, setDeleting]         = useState(false);

  const myId = user?._id || user?.id;
  const myInitial = user?.username?.[0]?.toUpperCase() || "M";

  useEffect(() => {
    getChats()
      .then((data) => {
        const list = Array.isArray(data.chats) ? data.chats : Array.isArray(data) ? data : [];
        setChats(list);
        if (list.length > 0) setSelectedChat(list[0]);
      })
      .catch((err) => setError(err.message || "Failed to load chats"))
      .finally(() => setLoading(false));
  }, []);

  const handleDelete = async (chatId) => {
    setDeleting(true);
    try {
      await deleteChat(chatId);
      const updated = chats.filter((c) => (c._id || c.id) !== chatId);
      setChats(updated);
      setSelectedChat(updated[0] || null);
    } catch (err) {
      setError(err.message || "Failed to delete");
    } finally {
      setDeleting(false);
    }
  };

  const filteredChats = chats.filter((chat) => {
    if (!searchFilter) return true;
    const { name } = getPartnerInfo(chat, myId);
    return name.toLowerCase().includes(searchFilter.toLowerCase());
  });

  const selectedMessages = selectedChat
    ? normalizeMessages(selectedChat.messages, myId)
    : [];

  const { name: selectedPartnerName, initial: selectedPartnerInitial } = selectedChat
    ? getPartnerInfo(selectedChat, myId)
    : { name: "", initial: "?" };

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
          <span className="text-[10px] bg-white/5 border border-white/10 px-2.5 py-1 rounded-full text-white/60 font-semibold tracking-wide">
            {chats.length} Saved Chat{chats.length !== 1 ? "s" : ""}
          </span>
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
                className="flex items-center gap-3 rounded-xl px-3 py-2.5 hover:bg-white/5 text-xs font-semibold text-white/60 hover:text-white transition-all">
                <IoIosAddCircle className="text-white/50" size={16} /> Post Something
              </Link>
              <Link to="/chat-history"
                className="flex items-center gap-3 rounded-xl px-3 py-2.5 bg-white/5 border border-white/5 text-xs font-semibold text-white transition-all">
                <FaHistory className="text-white/85" size={13} /> Chat History
              </Link>
              <Link to="/settings"
                className="flex items-center gap-3 rounded-xl px-3 py-2.5 hover:bg-white/5 text-xs font-semibold text-white/60 hover:text-white transition-all">
                <IoIosSettings className="text-white/50" size={15} /> Settings
              </Link>
            </div>
          </div>
        </aside>

        {/* Sidebar Saved Chats List Panel */}
        <aside className="w-64 flex-shrink-0 flex flex-col glass-panel rounded-3xl overflow-hidden p-4 gap-4">
          <div className="space-y-3">
            <div className="text-[10px] font-bold text-white/40 uppercase tracking-widest px-1">Saved Sessions</div>
            <div className="relative">
              <FaSearch className="absolute left-3.5 top-1/2 -translate-y-1/2 text-white/20 text-xs" />
              <input type="text" placeholder="Search by partner..."
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                className="w-full rounded-xl glass-input pl-9 pr-4 py-2.5 text-xs outline-none placeholder:text-white/20" />
            </div>
          </div>

          <div className="flex-1 min-h-0 overflow-y-auto space-y-1.5 pr-1 no-scrollbar">
            {loading && (
              <div className="flex items-center justify-center py-10">
                <div className="h-5 w-5 rounded-full border border-white border-t-transparent animate-spin" />
              </div>
            )}
            {!loading && filteredChats.length === 0 && (
              <div className="text-[10px] text-white/30 py-10 text-center">
                {chats.length === 0
                  ? "No saved chat sessions found."
                  : "No matches found."}
              </div>
            )}
            {filteredChats.map((chat) => {
              const cid = chat._id || chat.id;
              const { name, initial } = getPartnerInfo(chat, myId);
              const msgs = normalizeMessages(chat.messages, myId);
              const lastMsg = msgs[msgs.length - 1]?.text || "No messages";
              const isSelected = (selectedChat?._id || selectedChat?.id) === cid;

              return (
                <div key={cid} onClick={() => setSelectedChat(chat)}
                  className={`rounded-2xl p-3 cursor-pointer transition-all border border-transparent ${isSelected ? "bg-white/10 border-white/5" : "hover:bg-white/5"}`}>
                  <div className="flex items-center gap-3">
                    <div className="h-8 w-8 flex-shrink-0 rounded-xl bg-white text-black flex items-center justify-center text-xs font-bold">
                      {initial}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between gap-1">
                        <span className="text-xs font-bold text-white/90 truncate">{name}</span>
                        <span className="text-[9px] text-white/30 flex-shrink-0">{msgs.length}m</span>
                      </div>
                      <div className="text-[10px] text-white/40 truncate">{lastMsg}</div>
                      <div className="text-[9px] text-white/30 mt-0.5">{formatDate(chat.createdAt)}</div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </aside>

        {/* Main Conversation Details Panel */}
        <section className="flex-1 min-w-0 flex flex-col glass-panel rounded-3xl overflow-hidden p-6 gap-6">
          {error && (
            <div className="flex-shrink-0 text-xs text-rose-400 mb-3 px-4 py-2.5 bg-rose-500/5 rounded-xl border border-rose-500/20">
              {error}
            </div>
          )}

          {!selectedChat ? (
            <div className="flex-1 flex flex-col items-center justify-center text-white/30 gap-3 text-center">
              <FaFolderOpen size={36} className="text-white/20" />
              <p className="font-semibold text-sm">Select conversation</p>
              <p className="text-xs max-w-xs leading-relaxed">Choose a chat from the sidebar to review the conversation log.</p>
            </div>
          ) : (
            <>
              {/* Active Saved Chat Header */}
              <div className="flex-shrink-0 flex items-start justify-between gap-4 border-b border-white/5 pb-5 flex-wrap">
                <div className="flex items-center gap-3">
                  <div className="h-9 w-9 rounded-xl bg-white text-black flex items-center justify-center text-xs font-bold">
                    {selectedPartnerInitial}
                  </div>
                  <div>
                    <h2 className="text-sm font-bold text-white/95 truncate leading-snug">{selectedPartnerName}</h2>
                    <p className="text-[10px] text-white/40 mt-0.5">
                      {selectedChat.createdAt
                        ? new Date(selectedChat.createdAt).toLocaleDateString("en-US", {
                            weekday: "long", year: "numeric", month: "long", day: "numeric",
                          })
                        : "Date unknown"}
                      {" · "}
                      {selectedMessages.length} message{selectedMessages.length !== 1 ? "s" : ""}
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => handleDelete(selectedChat._id || selectedChat.id)}
                  disabled={deleting}
                  className="glass-btn px-4 py-2 rounded-full text-xs font-semibold text-rose-400 border-rose-500/20 hover:border-rose-500 hover:bg-rose-500/5 transition-all disabled:opacity-50 flex items-center gap-1.5">
                  <FaTrashAlt size={10} />
                  <span>{deleting ? "Deleting..." : "Delete Chat"}</span>
                </button>
              </div>

              {/* Chat timeline message display */}
              <div className="flex-1 min-h-0 overflow-y-auto pr-1 no-scrollbar relative">
                <div className="absolute left-[17px] top-0 bottom-0 w-px bg-white/5 pointer-events-none" />

                <div className="space-y-6 pb-4">
                  {selectedMessages.length === 0 ? (
                    <div className="text-xs text-white/30 py-4 pl-10">No messages saved in this session.</div>
                  ) : (
                    selectedMessages.map((msg, idx) => {
                      const isMe = msg.from === "me";
                      return (
                        <div key={idx} className="relative pl-12">
                          {/* Avatar */}
                          <div className={`absolute left-0 h-9 w-9 rounded-xl flex items-center justify-center text-xs font-bold flex-shrink-0 ${
                            isMe ? "bg-white/10 text-white border border-white/15" : "bg-white text-black"
                          }`}>
                            {isMe ? myInitial : selectedPartnerInitial}
                          </div>

                          <div className={isMe ? "text-right" : ""}>
                            <div className="text-[10px] font-semibold text-white/40 mb-1">
                              {isMe ? "You" : selectedPartnerName}
                            </div>
                            <div className={`inline-block rounded-2xl px-4 py-2.5 text-xs max-w-xl text-left leading-relaxed ${
                              isMe ? "bg-white text-black font-medium" : "bg-white/5 border border-white/5 text-white/90"
                            }`}>
                              {msg.text}
                            </div>
                            {msg.time && (
                              <div className="text-[9px] text-white/30 mt-1">{msg.time}</div>
                            )}
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            </>
          )}
        </section>
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
        <Link to="/post" className="flex flex-col items-center gap-1 text-white/45 hover:text-white text-xs transition-colors">
          <IoIosAddCircle size={18} />
          <span className="text-[9px] font-medium tracking-wide">Post</span>
        </Link>
        <Link to="/chat-history" className="flex flex-col items-center gap-1 text-white text-xs">
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
