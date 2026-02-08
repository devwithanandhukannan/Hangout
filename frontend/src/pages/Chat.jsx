import { useEffect, useState } from "react";
import { io } from "socket.io-client";

export default function Chat() {
  const [socket, setSocket] = useState(null);
  const [msg, setMsg] = useState("");
  const [messages, setMessages] = useState([]);

  useEffect(() => {
    const s = io("http://localhost:8000", {
      auth: {
        token: localStorage.getItem("token"), // optional if you expose token
      },
    });

    s.on("message", (data) => {
      setMessages((prev) => [...prev, data]);
    });

    setSocket(s);

    return () => s.disconnect();
  }, []);

  const send = () => {
    socket.emit("message", msg);
    setMsg("");
  };

  return (
    <div>
      <h2>Chat</h2>

      {messages.map((m, i) => (
        <p key={i}>{m}</p>
      ))}

      <input value={msg} onChange={(e) => setMsg(e.target.value)} />
      <button onClick={send}>Send</button>
    </div>
  );
}
