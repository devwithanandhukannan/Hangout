import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { getChats, deleteChat } from "../api";
import { useAuth } from "../AuthContext";

function getPartnerInfo(chat, myId) {
  if (!chat?.users) return { name: "Unknown", initial: "?" };
  const partner = chat.users.find((u) => {
    const uid = typeof u === "string" ? u : u?._id || u?.id;
    return uid?.toString() !== myId?.toString();
  });
  if (!partner) return { name: "Unknown", initial: "?" };
  const name =
    typeof partner === "string"
      ? `User#${partner.slice(-4)}`
      : partner.username || partner.name || `User#${partner._id?.toString().slice(-4)}`;
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
  const [chats, setChats]             = useState([]);
  const [selectedChat, setSelectedChat] = useState(null);
  const [loading, setLoading]         = useState(true);
  const [error, setError]             = useState("");
  const [searchFilter, setSearchFilter] = useState("");

  const myId = user?._id || user?.id;

  useEffect(() => {
    getChats()
      .then((data) => {
        const list = data.chats || data || [];
        setChats(list);
        if (list.length > 0) setSelectedChat(list[0]);
      })
      .catch((err) => setError(err.message || "Failed to load chats"))
      .finally(() => setLoading(false));
  }, []);

  const handleDelete = async (chatId) => {
    try {
      await deleteChat(chatId);
      const updated = chats.filter((c) => (c._id || c.id) !== chatId);
      setChats(updated);
      setSelectedChat(updated[0] || null);
    } catch (err) { setError(err.message || "Failed to delete"); }
  };

  const filteredChats = chats.filter((chat) => {
    if (!searchFilter) return true;
    const { name } = getPartnerInfo(chat, myId);
    return name.toLowerCase().includes(searchFilter.toLowerCase());
  });

  return (
    <div className="h-screen flex flex-col bg-black text-white antialiased overflow-hidden">

      {/* Header */}
      <div className="flex-shrink-0 px-4 sm:px-6 py-3 flex items-center gap-3 border-b border-white/10 bg-black/60 backdrop-blur">
        <Link to="/dashboard"
          className="h-8 w-8 flex-shrink-0 flex items-center justify-center rounded-full border border-white/30 hover:bg-white hover:text-black transition">
          ←
        </Link>
        <h1 className="text-base font-semibold">History</h1>
        <span className="text-[11px] text-gray-500">{chats.length} saved chat{chats.length !== 1 ? "s" : ""}</span>
      </div>

      {/* Body */}
      <main className="flex-1 min-h-0 px-2 sm:px-4 py-4 flex gap-4 overflow-hidden">

        {/* ── Sidebar ────────────────────────────────────────────────── */}
        <aside className="w-60 sm:w-64 flex-shrink-0 flex flex-col bg-white/5 border border-white/10 rounded-2xl overflow-hidden">
          <div className="flex-shrink-0 p-3 border-b border-white/10">
            <div className="text-xs font-semibold mb-2">Chats</div>
            <input type="text" placeholder="Search by partner"
              value={searchFilter} onChange={(e) => setSearchFilter(e.target.value)}
              className="w-full rounded-xl bg-black/60 border border-white/20 px-3 py-2 text-xs outline-none placeholder:text-gray-500" />
          </div>

          <div className="flex-1 min-h-0 overflow-y-auto px-2 py-2 space-y-1">
            {loading && (
              <div className="flex items-center justify-center py-10">
                <div className="h-5 w-5 rounded-full border-2 border-white border-t-transparent animate-spin" />
              </div>
            )}
            {!loading && filteredChats.length === 0 && (
              <div className="text-[11px] text-gray-400 px-2 py-6 text-center">
                {chats.length === 0
                  ? "No saved chats yet. Save a chat after your next Hangout!"
                  : "No chats match your search."}
              </div>
            )}
            {filteredChats.map((chat) => {
              const cid = chat._id || chat.id;
              const { name, initial } = getPartnerInfo(chat, myId);
              const msgCount = chat.messages?.length || 0;
              const lastMsg  = chat.messages?.[msgCount - 1]?.text || "";
              const isSelected = (selectedChat?._id || selectedChat?.id) === cid;

              return (
                <div key={cid} onClick={() => setSelectedChat(chat)}
                  className={`rounded-xl px-2.5 py-2 cursor-pointer transition ${isSelected ? "bg-white/10" : "hover:bg-white/5"}`}>
                  <div className="flex items-center gap-2">
                    <div className="h-7 w-7 flex-shrink-0 rounded-full bg-white text-black flex items-center justify-center text-xs font-semibold">
                      {initial}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between gap-1">
                        <span className="text-xs font-semibold truncate">{name}</span>
                        <span className="text-[10px] text-gray-400 flex-shrink-0">{msgCount}m</span>
                      </div>
                      <div className="text-[11px] text-gray-400 truncate">{lastMsg || "No messages"}</div>
                      <div className="text-[10px] text-gray-600 mt-0.5">{formatDate(chat.createdAt)}</div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </aside>

        {/* ── Main panel ─────────────────────────────────────────────── */}
        <section className="flex-1 min-w-0 flex flex-col bg-white/5 border border-white/10 rounded-2xl overflow-hidden px-6 py-5">
          {error && (
            <div className="flex-shrink-0 text-xs text-red-400 mb-3 px-3 py-2 bg-red-400/10 rounded-xl border border-red-400/20">{error}</div>
          )}

          {!selectedChat ? (
            <div className="flex-1 flex flex-col items-center justify-center text-gray-500 text-sm gap-3">
              {loading
                ? <div className="h-7 w-7 rounded-full border-2 border-white border-t-transparent animate-spin" />
                : <><span className="text-3xl">🗂</span><p>Select a chat to view</p></>}
            </div>
          ) : (
            <>
              {/* Chat header */}
              <div className="flex-shrink-0 mb-5 flex items-start justify-between gap-3 flex-wrap">
                <div>
                  <div className="text-base font-semibold">
                    Chat with {getPartnerInfo(selectedChat, myId).name}
                  </div>
                  <div className="text-xs text-gray-400 mt-1">
                    {selectedChat.createdAt
                      ? new Date(selectedChat.createdAt).toLocaleDateString("en-US", {
                          weekday: "long", year: "numeric", month: "long", day: "numeric",
                        })
                      : "Date unknown"}{" "}
                    · {selectedChat.messages?.length || 0} messages
                  </div>
                </div>
                <button onClick={() => handleDelete(selectedChat._id || selectedChat.id)}
                  className="flex-shrink-0 text-xs text-red-400 hover:text-red-300 border border-red-400/30 hover:border-red-300/50 px-3 py-1 rounded-full transition">
                  Delete chat
                </button>
              </div>

              {/* Timeline */}
              <div className="flex-1 min-h-0 overflow-y-auto relative">
                {/* Vertical line */}
                <div className="absolute left-4 top-0 bottom-0 w-px bg-white/15 pointer-events-none" />

                <div className="pl-10 space-y-6 pb-4">
                  {(selectedChat.messages || []).length === 0 ? (
                    <div className="text-[11px] text-gray-500 py-4">No messages in this chat.</div>
                  ) : (
                    (selectedChat.messages || []).map((msg, idx) => {
                      const senderId = typeof msg.senderId === "object" ? msg.senderId?._id || msg.senderId?.id : msg.senderId;
                      const isMe = senderId?.toString() === myId?.toString();
                      const { name: partnerName, initial: partnerInitial } = getPartnerInfo(selectedChat, myId);

                      return (
                        <div key={idx} className="relative">
                          {/* Avatar */}
                          <div className={`absolute -left-9 h-9 w-9 rounded-full flex items-center justify-center text-xs font-semibold flex-shrink-0 ${
                            isMe ? "bg-white/10 text-white border border-white/20" : "bg-white text-black"
                          }`}>
                            {isMe ? user?.username?.[0]?.toUpperCase() || "M" : partnerInitial}
                          </div>

                          <div className={isMe ? "text-right" : ""}>
                            <div className="text-xs font-semibold mb-1 text-gray-300">
                              {isMe ? "You" : partnerName}
                            </div>
                            <div className={`inline-block rounded-2xl px-4 py-2 text-sm max-w-xl text-left ${
                              isMe ? "bg-white text-black" : "bg-black border border-white/10 text-white"
                            }`}>
                              {msg.text}
                            </div>
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
    </div>
  );
}
