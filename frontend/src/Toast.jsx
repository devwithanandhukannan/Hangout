/**
 * Toast system — zero external dependencies.
 *
 * Usage:
 *   const toast = useToastHelpers();
 *   toast.success("Done!");
 *   toast.error("Oops", 5000);
 *   toast.action("Accept chat?", [
 *     { label: "✓ Accept", style: "primary",   fn: () => {} },
 *     { label: "✕ Decline", style: "secondary", fn: () => {} },
 *   ]);
 */
import {
  createContext, useContext, useCallback,
  useState, useEffect, useRef,
} from "react";

// ── Types / colours ────────────────────────────────────────────────────────
const ICONS = {
  success      : "✓",
  error        : "✕",
  info         : "ℹ",
  warning      : "⚠",
  follow       : "🤝",
  like         : "❤️",
  friend       : "🎉",
  message      : "💬",
  rank         : "★",
  notification : "🔔",
  chat_request : "💬",
};

const COLORS = {
  success      : "border-green-500/50  bg-green-950/90  text-green-100",
  error        : "border-red-500/50    bg-red-950/90    text-red-100",
  info         : "border-white/20      bg-zinc-900/90   text-white",
  warning      : "border-yellow-500/50 bg-yellow-950/90 text-yellow-100",
  follow       : "border-blue-500/50   bg-blue-950/90   text-blue-100",
  like         : "border-red-400/50    bg-red-950/90    text-red-100",
  friend       : "border-purple-500/50 bg-purple-950/90 text-purple-100",
  message      : "border-white/20      bg-zinc-900/90   text-white",
  rank         : "border-yellow-400/50 bg-yellow-950/90 text-yellow-100",
  notification : "border-white/15      bg-zinc-900/90   text-white",
  chat_request : "border-blue-400/60   bg-blue-950/95   text-blue-50",
};

// ── Context ────────────────────────────────────────────────────────────────
const ToastContext = createContext(null);

let _id = 0;

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  const addToast = useCallback((message, type = "info", duration = 3500, actions = null) => {
    const id = ++_id;
    setToasts((prev) => [...prev, { id, message, type, duration, actions }]);
    return id;
  }, []);

  const removeToast = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  return (
    <ToastContext.Provider value={{ addToast, removeToast }}>
      {children}

      {/* Container — stacked top-right, above everything */}
      <div
        aria-live="polite"
        aria-atomic="false"
        className="fixed top-4 right-4 z-[9999] flex flex-col gap-2 pointer-events-none w-[340px] max-w-[calc(100vw-2rem)]"
      >
        {toasts.map((t) => (
          <ToastItem key={t.id} toast={t} onRemove={removeToast} />
        ))}
      </div>
    </ToastContext.Provider>
  );
}

// ── Single toast item ──────────────────────────────────────────────────────
function ToastItem({ toast, onRemove }) {
  const [show, setShow]     = useState(false);
  const [leave, setLeave]   = useState(false);
  const timerRef            = useRef(null);

  useEffect(() => {
    // Tiny delay so CSS transition fires
    const t = setTimeout(() => setShow(true), 12);
    // Auto-dismiss timer
    const autoMs = toast.actions ? 30_000 : (toast.duration ?? 3500);
    timerRef.current = setTimeout(dismiss, autoMs);
    return () => {
      clearTimeout(t);
      clearTimeout(timerRef.current);
    };
  }, []); // eslint-disable-line

  function dismiss() {
    setLeave(true);
    setTimeout(() => onRemove(toast.id), 300);
  }

  function handleAction(fn) {
    clearTimeout(timerRef.current);
    fn();
    dismiss();
  }

  const color = COLORS[toast.type] ?? COLORS.info;
  const icon  = ICONS[toast.type]  ?? ICONS.info;

  return (
    <div
      role="alert"
      className={`
        pointer-events-auto
        flex flex-col gap-2
        px-4 py-3 rounded-2xl
        border backdrop-blur-2xl shadow-2xl
        text-sm font-medium
        transition-all duration-300 ease-out
        ${color}
        ${show && !leave ? "opacity-100 translate-x-0" : "opacity-0 translate-x-10"}
      `}
    >
      {/* Row: icon · message · close */}
      <div className="flex items-start gap-2.5">
        <span className="flex-shrink-0 mt-0.5 text-base">{icon}</span>
        <span className="flex-1 leading-snug">{toast.message}</span>
        <button
          onClick={dismiss}
          aria-label="Dismiss"
          className="flex-shrink-0 opacity-50 hover:opacity-100 transition-opacity text-xs mt-0.5 ml-1"
        >
          ✕
        </button>
      </div>

      {/* Action buttons (e.g. Accept / Decline direct chat request) */}
      {toast.actions && (
        <div className="flex gap-2 pl-7">
          {toast.actions.map((action, i) => (
            <button
              key={i}
              onClick={() => handleAction(action.fn)}
              className={`flex-1 py-1.5 rounded-xl text-xs font-semibold transition ${
                action.style === "primary"
                  ? "bg-white text-black hover:bg-gray-100 active:scale-95"
                  : "bg-white/10 text-white border border-white/20 hover:bg-white/20 active:scale-95"
              }`}
            >
              {action.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Hooks ─────────────────────────────────────────────────────────────────
export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be inside <ToastProvider>");
  return ctx;
}

/** Convenience wrapper with named helpers */
export function useToastHelpers() {
  const { addToast, removeToast } = useToast();

  return {
    // plain types
    toast   : (msg, ms) => addToast(msg, "info",         ms),
    success : (msg, ms) => addToast(msg, "success",      ms),
    error   : (msg, ms) => addToast(msg, "error",        ms),
    warning : (msg, ms) => addToast(msg, "warning",      ms),
    follow  : (msg, ms) => addToast(msg, "follow",       ms),
    like    : (msg, ms) => addToast(msg, "like",         ms),
    friend  : (msg, ms) => addToast(msg, "friend",       ms),
    message : (msg, ms) => addToast(msg, "message",      ms),
    rank    : (msg, ms) => addToast(msg, "rank",         ms),
    notif   : (msg, ms) => addToast(msg, "notification", ms),

    /**
     * Action toast — shows buttons.
     * @param {string}   msg
     * @param {{ label: string, style: "primary"|"secondary", fn: () => void }[]} actions
     * @param {number}   [ms=30000]
     */
    action : (msg, actions, ms) =>
      addToast(msg, "chat_request", ms ?? 30_000, actions),

    removeToast,
  };
}
