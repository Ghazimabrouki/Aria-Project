"use client";

import { motion } from "framer-motion";
import Image from "next/image";

interface AriaLoadingProps {
  message?: string;
  fullScreen?: boolean;
}

export function AriaLoading({ message = "Loading...", fullScreen = true }: AriaLoadingProps) {
  const container = fullScreen
    ? "fixed inset-0 z-50 flex flex-col items-center justify-center bg-background/90 backdrop-blur-sm"
    : "flex flex-col items-center justify-center py-16";

  return (
    <div className={container}>
      {/* Dark card that makes the logo pop on any theme */}
      <motion.div
        initial={{ opacity: 0, scale: 0.9 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.4, ease: "easeOut" }}
        className="relative flex flex-col items-center gap-5 rounded-2xl bg-black p-8 shadow-2xl ring-1 ring-white/10"
      >
        {/* Gradient glow behind logo */}
        <div className="absolute inset-0 rounded-2xl opacity-40 blur-2xl"
          style={{
            background: "radial-gradient(circle at center, rgba(99,102,241,0.4) 0%, rgba(168,85,247,0.2) 50%, transparent 70%)",
          }}
        />

        {/* Logo with subtle breathe animation */}
        <motion.div
          className="relative"
          animate={{ scale: [1, 1.04, 1] }}
          transition={{ duration: 2.5, repeat: Infinity, ease: "easeInOut" }}
        >
          <Image
            src="/aria-logo.png"
            alt="ARIA"
            width={72}
            height={72}
            className="rounded-xl object-contain"
            priority
          />
        </motion.div>

        {/* Message */}
        <p className="relative text-sm font-medium text-white/90 tracking-wide">
          {message}
        </p>

        {/* Single clean progress bar */}
        <div className="relative h-0.5 w-32 overflow-hidden rounded-full bg-white/10">
          <motion.div
            className="h-full rounded-full"
            style={{
              background: "linear-gradient(90deg, #3b82f6, #a855f7)",
            }}
            animate={{ x: ["-100%", "100%"] }}
            transition={{
              duration: 1.2,
              repeat: Infinity,
              ease: "easeInOut",
            }}
          />
        </div>
      </motion.div>
    </div>
  );
}
