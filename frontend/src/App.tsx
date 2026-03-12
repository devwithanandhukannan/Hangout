import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider } from "./AuthContext";
import { ToastProvider } from "./Toast";
import { SocketProvider } from "./SocketContext";
import ProtectedRoute from "./ProtectedRoute";
import LandingPage from "./pages/LandingPage";
import LoginPage from "./pages/LoginPage";
import SignupPage from "./pages/SignupPage";
import ForgotPasswordPage from "./pages/ForgotPasswordPage";
import DashboardPage from "./pages/DashboardPage";
import ChatPage from "./pages/ChatPage";
import ChatHistoryPage from "./pages/ChatHistoryPage";
import FeedPage from "./pages/FeedPage";
import PostPage from "./pages/PostPage";
import SettingsPage from "./pages/SettingsPage";

// BrowserRouter MUST be the outermost wrapper so that useNavigate
// works inside SocketProvider and all other providers.
export function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <ToastProvider>
          <SocketProvider>
            <Routes>
              {/* ── Public ───────────────────────────────────────────── */}
              <Route path="/"                element={<LandingPage />} />
              <Route path="/login"           element={<LoginPage />} />
              <Route path="/signup"          element={<SignupPage />} />
              <Route path="/forgot-password" element={<ForgotPasswordPage />} />

              {/* ── Protected ─────────────────────────────────────────── */}
              <Route path="/dashboard"    element={<ProtectedRoute><DashboardPage /></ProtectedRoute>} />
              <Route path="/chat"         element={<ProtectedRoute><ChatPage /></ProtectedRoute>} />
              <Route path="/chat-history" element={<ProtectedRoute><ChatHistoryPage /></ProtectedRoute>} />
              <Route path="/feed"         element={<ProtectedRoute><FeedPage /></ProtectedRoute>} />
              <Route path="/post"         element={<ProtectedRoute><PostPage /></ProtectedRoute>} />
              <Route path="/settings"     element={<ProtectedRoute><SettingsPage /></ProtectedRoute>} />

              {/* ── Fallback ──────────────────────────────────────────── */}
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </SocketProvider>
        </ToastProvider>
      </AuthProvider>
    </BrowserRouter>
  );
}
