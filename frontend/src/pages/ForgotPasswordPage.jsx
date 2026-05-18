import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { sendOtp, verifyOtp, resetPassword } from "../api";
import { FaEnvelope, FaKey, FaLock, FaArrowRight, FaArrowLeft } from "react-icons/fa";

export default function ForgotPasswordPage() {
    const navigate = useNavigate();

    const [step, setStep] = useState("forgot"); // forgot → otp → reset
    const [email, setEmail] = useState("");
    const [otp, setOtp] = useState("");
    const [password, setPassword] = useState("");
    const [confirmPassword, setConfirmPassword] = useState("");
    const [loading, setLoading] = useState(false);
    const [message, setMessage] = useState({ text: "", type: "" });

    const showMessage = (text, type = "error") => {
        setMessage({ text, type });
        setTimeout(() => setMessage({ text: "", type: "" }), 4000);
    };

    // ── Step 1: Send OTP ─────────────────────────────────────────────────
    const handleSendOtp = async (e) => {
        e.preventDefault();

        if (!email) {
            showMessage("Please enter your email address");
            return;
        }
        if (!/^\S+@\S+\.\S+$/.test(email)) {
            showMessage("Please enter a valid email address");
            return;
        }

        setLoading(true);
        try {
            await sendOtp(email);
            showMessage(`OTP sent to ${email}`, "success");
            setStep("otp");
        } catch (error) {
            showMessage(error.message);
        } finally {
            setLoading(false);
        }
    };

    // ── Step 2: Verify OTP ───────────────────────────────────────────────
    const handleVerifyOtp = async (e) => {
        e.preventDefault();

        if (!otp || !/^\d{6}$/.test(otp)) {
            showMessage("Please enter a valid 6-digit OTP");
            return;
        }

        setLoading(true);
        try {
            await verifyOtp(email, otp);
            showMessage("OTP verified! Set a new password", "success");
            setStep("reset");
        } catch (error) {
            showMessage(error.message);
        } finally {
            setLoading(false);
        }
    };

    // ── Step 3: Reset Password ───────────────────────────────────────────
    const handleResetPassword = async (e) => {
        e.preventDefault();

        if (!password || password.length < 6) {
            showMessage("Password must be at least 6 characters");
            return;
        }
        if (password !== confirmPassword) {
            showMessage("Passwords do not match");
            return;
        }

        setLoading(true);
        try {
            await resetPassword(email, password);
            showMessage("Password updated successfully!", "success");
            setTimeout(() => navigate("/login"), 1500);
        } catch (error) {
            showMessage(error.message);
        } finally {
            setLoading(false);
        }
    };

    // ── Resend OTP ───────────────────────────────────────────────────────
    const handleResendOtp = async () => {
        setLoading(true);
        try {
            await sendOtp(email);
            showMessage(`New OTP sent to ${email}`, "success");
            setOtp("");
        } catch (error) {
            showMessage(error.message);
        } finally {
            setLoading(false);
        }
    };

    const handleBackToEmail = () => {
        setStep("forgot");
        setOtp("");
    };

    const Spinner = () => (
        <div className="w-4 h-4 border-2 border-black border-t-transparent rounded-full animate-spin" />
    );

    return (
        <div className="min-h-screen bg-[#030303] text-white antialiased flex flex-col relative overflow-hidden">
            {/* Background radial glow */}
            <div className="absolute top-[-10%] right-[-10%] w-[50%] h-[50%] rounded-full bg-blue-500/5 blur-[120px] pointer-events-none pulse-glow-bg" />
            <div className="absolute bottom-[-15%] left-[-10%] w-[50%] h-[50%] rounded-full bg-rose-500/5 blur-[120px] pointer-events-none pulse-glow-bg" style={{ animationDelay: "-4s" }} />

            <header className="w-full border-b border-white/5 bg-black/20 backdrop-blur-md z-10">
                <div className="max-w-5xl mx-auto px-6 py-5 flex items-center justify-between">
                    <Link to="/" className="flex items-center gap-2">
                        <div className="h-6 w-6 rounded-lg bg-white flex items-center justify-center font-black text-black text-xs tracking-wider">H</div>
                        <span className="font-bold tracking-tight text-sm text-white/90">Hangout</span>
                    </Link>
                    <nav className="flex items-center gap-6 text-xs text-white/50">
                        <Link to="/login" className="hover:text-white transition-colors">Sign In</Link>
                    </nav>
                </div>
            </header>

            {message.text && (
                <div
                    className={`fixed top-24 left-1/2 -translate-x-1/2 z-50 px-6 py-3 rounded-full text-xs font-semibold backdrop-blur-lg border transition-all ${
                        message.type === "success"
                            ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-300"
                            : "bg-rose-500/10 border-rose-500/20 text-rose-300"
                    }`}
                >
                    {message.text}
                </div>
            )}

            <main className="flex-1 flex items-center justify-center px-6 py-10 z-10">
                <div className="w-full max-w-[420px] glass-panel rounded-3xl p-8 space-y-6 animate-float" style={{ animationDuration: "12s" }}>
                    
                    {/* ── STEP 1: EMAIL ── */}
                    {step === "forgot" && (
                        <div className="space-y-6">
                            <div className="text-center space-y-2">
                                <h1 className="text-2xl font-bold tracking-tight bg-gradient-to-b from-white to-white/70 bg-clip-text text-transparent">
                                    Forgot password?
                                </h1>
                                <p className="text-xs text-white/50">
                                    Enter your registered email address. We will send you a 6-digit OTP to reset your password.
                                </p>
                            </div>

                            <form onSubmit={handleSendOtp} className="space-y-4">
                                <div className="space-y-1.5">
                                    <label htmlFor="reset-email" className="block text-xs font-semibold tracking-wide text-white/60">
                                        Email Address
                                    </label>
                                    <div className="relative">
                                        <FaEnvelope className="absolute left-4 top-1/2 -translate-y-1/2 text-white/30 text-xs" />
                                        <input
                                            id="reset-email"
                                            type="email"
                                            required
                                            placeholder="hello@hangout.com"
                                            value={email}
                                            onChange={(e) => setEmail(e.target.value)}
                                            className="w-full rounded-xl glass-input pl-10 pr-4 py-3 text-xs outline-none focus:border-white focus:bg-white/[0.06]"
                                        />
                                    </div>
                                </div>

                                <button
                                    type="submit"
                                    disabled={loading}
                                    className="w-full glass-btn-primary py-3 rounded-full text-xs font-semibold flex items-center justify-center gap-2 disabled:opacity-50 mt-2"
                                >
                                    {loading ? <Spinner /> : "Send OTP"}
                                    <FaArrowRight size={10} />
                                </button>
                            </form>

                            <p className="text-xs text-center text-white/50">
                                <Link to="/login" className="text-white hover:underline font-semibold transition-colors">
                                    Back to login
                                </Link>
                            </p>
                        </div>
                    )}

                    {/* ── STEP 2: OTP ── */}
                    {step === "otp" && (
                        <div className="space-y-6">
                            <div className="text-center space-y-2">
                                <div className="mx-auto w-10 h-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center mb-1">
                                    <FaKey className="text-white/70 text-sm" />
                                </div>
                                <h1 className="text-2xl font-bold tracking-tight bg-gradient-to-b from-white to-white/70 bg-clip-text text-transparent">
                                    Verify OTP
                                </h1>
                                <p className="text-xs text-white/50">
                                    We sent a 6-digit code to <span className="text-white font-medium">{email}</span>.
                                </p>
                            </div>

                            <form onSubmit={handleVerifyOtp} className="space-y-4">
                                <div className="space-y-1.5">
                                    <label htmlFor="otpCode" className="block text-xs font-semibold tracking-wide text-white/60">
                                        One-Time Password
                                    </label>
                                    <input
                                        id="otpCode"
                                        type="text"
                                        inputMode="numeric"
                                        maxLength={6}
                                        value={otp}
                                        onChange={(e) => setOtp(e.target.value.replace(/[^0-9]/g, "").slice(0, 6))}
                                        placeholder="000000"
                                        className="w-full rounded-xl glass-input py-3 text-sm text-center tracking-[0.25em] font-mono outline-none focus:border-white focus:bg-white/[0.06]"
                                    />
                                    <p className="text-[10px] text-white/30 text-right">Valid for 5 minutes</p>
                                </div>

                                <button
                                    type="submit"
                                    disabled={loading}
                                    className="w-full glass-btn-primary py-3 rounded-full text-xs font-semibold flex items-center justify-center gap-2 disabled:opacity-50 mt-2"
                                >
                                    {loading ? <Spinner /> : "Verify Code"}
                                    <FaArrowRight size={10} />
                                </button>

                                <div className="text-center pt-1">
                                    <button
                                        type="button"
                                        onClick={handleResendOtp}
                                        disabled={loading}
                                        className="text-[10px] text-white/50 hover:text-white transition-colors underline underline-offset-2"
                                    >
                                        Resend OTP
                                    </button>
                                </div>
                            </form>

                            <p className="text-xs text-center text-white/50">
                                <button
                                    onClick={handleBackToEmail}
                                    className="text-white/60 hover:text-white transition-colors flex items-center gap-1 mx-auto text-xs"
                                >
                                    <FaArrowLeft size={10} />
                                    Change Email
                                </button>
                            </p>
                        </div>
                    )}

                    {/* ── STEP 3: RESET ── */}
                    {step === "reset" && (
                        <div className="space-y-6">
                            <div className="text-center space-y-2">
                                <div className="mx-auto w-10 h-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center mb-1">
                                    <FaLock className="text-white/70 text-sm" />
                                </div>
                                <h1 className="text-2xl font-bold tracking-tight bg-gradient-to-b from-white to-white/70 bg-clip-text text-transparent">
                                    New password
                                </h1>
                                <p className="text-xs text-white/50">
                                    Set a strong password for your account.
                                </p>
                            </div>

                            <form onSubmit={handleResetPassword} className="space-y-4">
                                <div className="space-y-3">
                                    <div className="space-y-1.5">
                                        <label htmlFor="newPassword" className="block text-xs font-semibold tracking-wide text-white/60">
                                            New Password
                                        </label>
                                        <div className="relative">
                                            <FaLock className="absolute left-4 top-1/2 -translate-y-1/2 text-white/30 text-xs" />
                                            <input
                                                id="newPassword"
                                                type="password"
                                                required
                                                placeholder="••••••••"
                                                value={password}
                                                onChange={(e) => setPassword(e.target.value)}
                                                className="w-full rounded-xl glass-input pl-10 pr-4 py-3 text-xs outline-none focus:border-white focus:bg-white/[0.06]"
                                            />
                                        </div>
                                    </div>
                                    <div className="space-y-1.5">
                                        <label htmlFor="confirmPassword" className="block text-xs font-semibold tracking-wide text-white/60">
                                            Confirm Password
                                        </label>
                                        <div className="relative">
                                            <FaLock className="absolute left-4 top-1/2 -translate-y-1/2 text-white/30 text-xs" />
                                            <input
                                                id="confirmPassword"
                                                type="password"
                                                required
                                                placeholder="••••••••"
                                                value={confirmPassword}
                                                onChange={(e) => setConfirmPassword(e.target.value)}
                                                className="w-full rounded-xl glass-input pl-10 pr-4 py-3 text-xs outline-none focus:border-white focus:bg-white/[0.06]"
                                            />
                                        </div>
                                    </div>
                                </div>

                                <button
                                    type="submit"
                                    disabled={loading}
                                    className="w-full glass-btn-primary py-3 rounded-full text-xs font-semibold flex items-center justify-center gap-2 disabled:opacity-50 mt-2"
                                >
                                    {loading ? <Spinner /> : "Reset Password"}
                                    <FaArrowRight size={10} />
                                </button>
                            </form>
                        </div>
                    )}
                </div>
            </main>
        </div>
    );
}