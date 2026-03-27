import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { sendOtp, verifyOtp, resetPassword } from "../api";

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
            showMessage(
                "🎉 Password updated successfully! Redirecting…",
                "success"
            );
            setTimeout(() => navigate("/login"), 2000);
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

    // ── Spinner component ────────────────────────────────────────────────
    const Spinner = () => (
        <div className="w-4 h-4 border-2 border-black border-t-transparent rounded-full animate-spin" />
    );

    return (
        <div className="min-h-screen bg-black text-white antialiased flex flex-col relative overflow-hidden">
            {/* Background gradient */}
            <div className="pointer-events-none absolute inset-0 -z-10 opacity-60 bg-[radial-gradient(circle_at_top,_rgba(255,255,255,0.12),transparent_60%),radial-gradient(circle_at_bottom,_rgba(255,255,255,0.08),transparent_65%)]" />

            {/* Header */}
            <header className="w-full border-b border-white/10">
                <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex items-center justify-between text-sm">
                    <div className="font-semibold tracking-tight text-white/80">
                        Hangout
                    </div>
                    <nav className="flex items-center gap-4 text-xs sm:text-sm text-white/70">
                        <a
                            href="#"
                            className="hover:text-white transition-colors"
                        >
                            About
                        </a>
                        <a
                            href="#"
                            className="hover:text-white transition-colors"
                        >
                            Privacy &amp; Security
                        </a>
                    </nav>
                </div>
            </header>

            {/* Toast */}
            {message.text && (
                <div
                    className={`fixed bottom-6 left-1/2 -translate-x-1/2 z-50
                        px-6 py-3 rounded-full text-sm font-medium
                        backdrop-blur-lg border transition-all ${
                            message.type === "success"
                                ? "bg-green-500/20 border-green-500/50 text-green-100"
                                : "bg-red-500/20 border-red-500/50 text-red-100"
                        }`}
                >
                    {message.text}
                </div>
            )}

            <main className="flex-1 flex items-center justify-center px-4 sm:px-6 lg:px-8 py-10">
                <div
                    className="w-full max-w-md bg-white/5 border border-white/10
                        rounded-3xl backdrop-blur-xl
                        shadow-[0_0_45px_rgba(0,0,0,0.85)]
                        px-6 sm:px-8 py-8 space-y-6"
                >
                    {/* ────────────── STEP 1: EMAIL ────────────── */}
                    {step === "forgot" && (
                        <div className="space-y-6">
                            <div className="text-center space-y-2">
                                <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight">
                                    Forgot your password?
                                </h1>
                                <p className="text-xs sm:text-sm text-white/60">
                                    Enter the email you use for Hangout.
                                    We'll send a 6-digit OTP to reset
                                    your password.
                                </p>
                            </div>

                            <form
                                onSubmit={handleSendOtp}
                                className="space-y-5"
                            >
                                <div className="space-y-1.5">
                                    <label
                                        htmlFor="reset-email"
                                        className="block text-xs font-medium tracking-wide text-white/70"
                                    >
                                        Email address
                                    </label>
                                    <input
                                        id="reset-email"
                                        type="email"
                                        required
                                        value={email}
                                        onChange={(e) =>
                                            setEmail(e.target.value)
                                        }
                                        placeholder="hello@hangout.com"
                                        className="w-full rounded-xl bg-black/40
                                            border border-white/20 px-3 py-2.5
                                            text-sm outline-none
                                            focus:border-white focus:bg-black/60
                                            transition-colors"
                                    />
                                </div>

                                <button
                                    type="submit"
                                    disabled={loading}
                                    className="w-full inline-flex items-center
                                        justify-center rounded-full bg-white
                                        text-black text-sm font-semibold py-2.5
                                        border border-white hover:bg-black
                                        hover:text-white transition-colors
                                        disabled:opacity-50
                                        disabled:cursor-not-allowed gap-2"
                                >
                                    {loading ? (
                                        <Spinner />
                                    ) : (
                                        "Send reset email"
                                    )}
                                </button>
                            </form>

                            <p className="text-xs text-center text-white/60">
                                Remembered your password?{" "}
                                <Link
                                    to="/login"
                                    className="text-white hover:underline font-medium"
                                >
                                    Back to login
                                </Link>
                                .
                            </p>
                        </div>
                    )}

                    {/* ────────────── STEP 2: OTP ────────────── */}
                    {step === "otp" && (
                        <div className="space-y-6">
                            <div className="text-center space-y-2">
                                <div
                                    className="mx-auto w-12 h-12 rounded-full
                                        bg-white/10 flex items-center
                                        justify-center mb-1"
                                >
                                    <svg
                                        className="w-5 h-5 text-white/80"
                                        fill="none"
                                        stroke="currentColor"
                                        viewBox="0 0 24 24"
                                    >
                                        <path
                                            strokeLinecap="round"
                                            strokeLinejoin="round"
                                            strokeWidth={1.5}
                                            d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743
                                               5.743L11 17H9v2H7v2H4a1 1 0
                                               01-1-1v-2.586a1 1 0
                                               01.293-.707l5.964-5.964A6 6 0 1121 9z"
                                        />
                                    </svg>
                                </div>
                                <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight">
                                    Verify OTP
                                </h1>
                                <p className="text-xs sm:text-sm text-white/60">
                                    We sent a 6-digit code to{" "}
                                    <span className="text-white font-medium">
                                        {email}
                                    </span>
                                    . Please enter it below.
                                </p>
                            </div>

                            <form
                                onSubmit={handleVerifyOtp}
                                className="space-y-5"
                            >
                                <div className="space-y-1.5">
                                    <label
                                        htmlFor="otpCode"
                                        className="block text-xs font-medium tracking-wide text-white/70"
                                    >
                                        One-time password
                                    </label>
                                    <input
                                        id="otpCode"
                                        type="text"
                                        inputMode="numeric"
                                        maxLength={6}
                                        value={otp}
                                        onChange={(e) =>
                                            setOtp(
                                                e.target.value
                                                    .replace(/[^0-9]/g, "")
                                                    .slice(0, 6)
                                            )
                                        }
                                        placeholder="000000"
                                        className="w-full rounded-xl bg-black/40
                                            border border-white/20 px-3 py-2.5
                                            text-sm text-center tracking-wider
                                            font-mono text-base outline-none
                                            focus:border-white focus:bg-black/60
                                            transition-colors"
                                    />
                                    <p className="text-[11px] text-white/40 text-right">
                                        Valid for 5 minutes
                                    </p>
                                </div>

                                <button
                                    type="submit"
                                    disabled={loading}
                                    className="w-full inline-flex items-center
                                        justify-center rounded-full bg-white
                                        text-black text-sm font-semibold py-2.5
                                        border border-white hover:bg-black
                                        hover:text-white transition-colors
                                        disabled:opacity-50
                                        disabled:cursor-not-allowed gap-2"
                                >
                                    {loading ? <Spinner /> : "Verify OTP"}
                                </button>

                                <div className="text-center">
                                    <button
                                        type="button"
                                        onClick={handleResendOtp}
                                        disabled={loading}
                                        className="text-xs text-white/60
                                            hover:text-white transition-colors
                                            underline underline-offset-2
                                            disabled:opacity-50"
                                    >
                                        Resend OTP
                                    </button>
                                </div>
                            </form>

                            <p className="text-xs text-center text-white/60">
                                <button
                                    onClick={handleBackToEmail}
                                    className="text-white/70 hover:text-white transition-colors"
                                >
                                    ← Use different email
                                </button>
                            </p>
                        </div>
                    )}

                    {/* ────────────── STEP 3: RESET ────────────── */}
                    {step === "reset" && (
                        <div className="space-y-6">
                            <div className="text-center space-y-2">
                                <div
                                    className="mx-auto w-12 h-12 rounded-full
                                        bg-white/10 flex items-center
                                        justify-center mb-1"
                                >
                                    <svg
                                        className="w-5 h-5 text-white/80"
                                        fill="none"
                                        stroke="currentColor"
                                        viewBox="0 0 24 24"
                                    >
                                        <path
                                            strokeLinecap="round"
                                            strokeLinejoin="round"
                                            strokeWidth={1.5}
                                            d="M12 15v2m-6-4h12a2 2 0 012
                                               2v6a2 2 0 01-2 2H6a2 2 0
                                               01-2-2v-6a2 2 0 012-2zm10-10V5a2
                                               2 0 00-2-2h-4a2 2 0 00-2 2v2h8z"
                                        />
                                    </svg>
                                </div>
                                <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight">
                                    Create new password
                                </h1>
                                <p className="text-xs sm:text-sm text-white/60">
                                    Choose a strong password for{" "}
                                    <span className="text-white font-medium">
                                        {email}
                                    </span>
                                </p>
                            </div>

                            <form
                                onSubmit={handleResetPassword}
                                className="space-y-5"
                            >
                                <div className="space-y-3">
                                    <div>
                                        <label
                                            htmlFor="newPassword"
                                            className="block text-xs font-medium tracking-wide text-white/70 mb-1"
                                        >
                                            New password
                                        </label>
                                        <input
                                            id="newPassword"
                                            type="password"
                                            value={password}
                                            onChange={(e) =>
                                                setPassword(e.target.value)
                                            }
                                            placeholder="••••••••"
                                            className="w-full rounded-xl bg-black/40
                                                border border-white/20 px-3 py-2.5
                                                text-sm outline-none
                                                focus:border-white
                                                focus:bg-black/60
                                                transition-colors"
                                        />
                                    </div>
                                    <div>
                                        <label
                                            htmlFor="confirmPassword"
                                            className="block text-xs font-medium tracking-wide text-white/70 mb-1"
                                        >
                                            Confirm password
                                        </label>
                                        <input
                                            id="confirmPassword"
                                            type="password"
                                            value={confirmPassword}
                                            onChange={(e) =>
                                                setConfirmPassword(
                                                    e.target.value
                                                )
                                            }
                                            placeholder="••••••••"
                                            className="w-full rounded-xl bg-black/40
                                                border border-white/20 px-3 py-2.5
                                                text-sm outline-none
                                                focus:border-white
                                                focus:bg-black/60
                                                transition-colors"
                                        />
                                    </div>
                                </div>

                                <button
                                    type="submit"
                                    disabled={loading}
                                    className="w-full inline-flex items-center
                                        justify-center rounded-full bg-white
                                        text-black text-sm font-semibold py-2.5
                                        border border-white hover:bg-black
                                        hover:text-white transition-colors
                                        disabled:opacity-50
                                        disabled:cursor-not-allowed gap-2"
                                >
                                    {loading ? (
                                        <Spinner />
                                    ) : (
                                        "Reset password"
                                    )}
                                </button>
                            </form>

                            <p className="text-xs text-center text-white/60">
                                <Link
                                    to="/login"
                                    className="text-white hover:underline font-medium"
                                >
                                    Return to login
                                </Link>
                            </p>
                        </div>
                    )}
                </div>
            </main>
        </div>
    );
}