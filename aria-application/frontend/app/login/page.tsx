"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { AlertCircle, Server, Lock } from "lucide-react";
import ShaderBackground from "@/components/ui/shader-background";
import AnimatedTextCycle from "@/components/ui/animated-text-cycle";

export default function LoginPage() {
  const router = useRouter();
  const { login, user, isLoading } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (user) {
      router.push("/");
    }
  }, [user, router]);

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="animate-pulse text-muted-foreground">Loading...</div>
      </div>
    );
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    if (!username.trim() || !password.trim()) {
      setError("Please enter both username and password.");
      return;
    }
    setSubmitting(true);
    try {
      await login(username.trim(), password.trim());
      router.push("/");
    } catch (err: any) {
      setError(err.message || "Invalid credentials.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen relative flex items-center justify-center px-4 bg-slate-950">
      <ShaderBackground />

      <div className="relative z-10 w-full max-w-lg">
        {/* Glow ring behind card */}
        <div className="absolute -inset-1 rounded-2xl bg-gradient-to-b from-primary/20 via-primary/5 to-transparent blur-xl opacity-60" />

        <div className="relative rounded-2xl border border-white/[0.08] bg-slate-950/50 backdrop-blur-2xl shadow-2xl shadow-black/40 overflow-hidden">
          {/* Subtle top gradient line */}
          <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-primary/40 to-transparent" />

          {/* Inner radial glow */}
          <div className="absolute top-0 left-1/2 -translate-x-1/2 w-96 h-96 bg-primary/5 rounded-full blur-3xl pointer-events-none" />

          <div className="relative p-8 md:p-10">
            {/* Branding Section */}
            <div className="flex flex-col items-center text-center">
              {/* Logo */}
              <div className="relative mb-6">
                <div className="absolute inset-0 rounded-2xl bg-primary/20 blur-xl animate-pulse" />
                <div className="relative h-20 w-20 rounded-2xl overflow-hidden ring-1 ring-primary/30 border border-primary/20 shadow-lg shadow-primary/10">
                  <img
                    src="/aria-logo.png"
                    alt="ARIA Security Platform"
                    className="h-full w-full object-contain"
                  />
                </div>
              </div>

              <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-white">
                ARIA Security Platform
              </h1>

              <div className="mt-3 text-lg md:text-xl font-light text-slate-300">
                Your{" "}
                <AnimatedTextCycle
                  words={[
                    "infrastructure",
                    "SOC",
                    "network",
                    "endpoints",
                    "threat landscape",
                    "cloud",
                    "containers",
                    "data",
                  ]}
                  interval={2500}
                  className="text-primary"
                />
                {" "}deserves better
              </div>

              <p className="text-[11px] text-slate-500 mt-2 tracking-[0.2em] uppercase font-medium">
                Adaptive Response Intelligence Automation
              </p>
            </div>

            {/* Divider */}
            <div className="relative my-8">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-white/[0.06]" />
              </div>
              <div className="relative flex justify-center">
                <div className="flex items-center gap-2 bg-slate-950/0 px-3">
                  <Lock className="h-3 w-3 text-primary/60" />
                  <span className="text-[10px] uppercase tracking-widest text-slate-500 font-medium">
                    Secure Access
                  </span>
                  <Lock className="h-3 w-3 text-primary/60" />
                </div>
              </div>
            </div>

            {/* Form Section */}
            <div>
              <h2 className="text-sm font-semibold text-white mb-1">Sign In</h2>
              <p className="text-xs text-slate-400 mb-5">
                Enter your credentials to continue
              </p>

              <form onSubmit={handleSubmit} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="username" className="text-slate-300 text-xs uppercase tracking-wider font-medium">
                    Username
                  </Label>
                  <div className="relative group">
                    <Server className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500 group-focus-within:text-primary transition-colors" />
                    <Input
                      id="username"
                      placeholder="Email or server IP"
                      className="pl-9 bg-slate-900/60 border-white/[0.08] text-slate-100 placeholder:text-slate-600 focus:border-primary/40 focus:ring-primary/20"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      autoComplete="username"
                      disabled={submitting}
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="password" className="text-slate-300 text-xs uppercase tracking-wider font-medium">
                    Password
                  </Label>
                  <div className="relative group">
                    <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500 group-focus-within:text-primary transition-colors" />
                    <Input
                      id="password"
                      type="password"
                      placeholder="••••••••"
                      className="pl-9 bg-slate-900/60 border-white/[0.08] text-slate-100 placeholder:text-slate-600 focus:border-primary/40 focus:ring-primary/20"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      autoComplete="current-password"
                      disabled={submitting}
                    />
                  </div>
                </div>

                {error && (
                  <div className="flex items-start gap-2 rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-sm text-red-400">
                    <AlertCircle className="h-4 w-4 mt-0.5 shrink-0" />
                    <span>{error}</span>
                  </div>
                )}

                <Button
                  type="submit"
                  className="w-full bg-primary hover:bg-primary/90 text-primary-foreground font-semibold tracking-wide"
                  disabled={submitting}
                >
                  {submitting ? "Authenticating..." : "Sign In"}
                </Button>
              </form>
            </div>

            {/* Footer inside card */}
            <div className="mt-8 pt-6 border-t border-white/[0.06] text-center">
              <p className="text-[10px] text-slate-600 tracking-wide">
                ARIA — Adaptive Response Intelligence Automation
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
