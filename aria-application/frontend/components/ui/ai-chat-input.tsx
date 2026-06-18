"use client";

import * as React from "react";
import { useState, useEffect, useRef } from "react";
import { Lightbulb, Globe, Send, Loader2 } from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { cn } from "@/lib/utils";

const PLACEHOLDERS = [
  "What are the most critical alerts right now?",
  "Summarize open incidents across all assets...",
  "Check disk usage on the target host",
  "Block IP 10.0.0.5 on the firewall",
  "Restart nginx and verify it's running",
  "Clean up old log files older than 30 days",
];

export interface AIChatInputProps {
  value: string;
  onChange: (value: string) => void;
  onSubmit: () => void;
  placeholder?: string;
  placeholders?: string[];
  disabled?: boolean;
  isLoading?: boolean;
  maxLength?: number;
  thinkActive?: boolean;
  onThinkToggle?: () => void;
  deepSearchActive?: boolean;
  onDeepSearchToggle?: () => void;
  showCharCount?: boolean;
}

export function AIChatInput({
  value,
  onChange,
  onSubmit,
  placeholder,
  placeholders: customPlaceholders,
  disabled = false,
  isLoading = false,
  maxLength,
  thinkActive = false,
  onThinkToggle,
  deepSearchActive = false,
  onDeepSearchToggle,
  showCharCount = false,
}: AIChatInputProps) {
  const [placeholderIndex, setPlaceholderIndex] = useState(0);
  const [showPlaceholder, setShowPlaceholder] = useState(true);
  const [isActive, setIsActive] = useState(false);
  const wrapperRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const placeholders = customPlaceholders && customPlaceholders.length > 0
    ? customPlaceholders
    : placeholder
      ? [placeholder, ...PLACEHOLDERS]
      : PLACEHOLDERS;

  // Cycle placeholder text when input is inactive
  useEffect(() => {
    if (isActive || value) return;

    const interval = setInterval(() => {
      setShowPlaceholder(false);
      setTimeout(() => {
        setPlaceholderIndex((prev) => (prev + 1) % placeholders.length);
        setShowPlaceholder(true);
      }, 400);
    }, 3000);

    return () => clearInterval(interval);
  }, [isActive, value, placeholders.length]);

  // Close input expand when clicking outside (but keep value)
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        wrapperRef.current &&
        !wrapperRef.current.contains(event.target as Node)
      ) {
        if (!value) setIsActive(false);
      }
    };

    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [value]);

  const handleActivate = () => {
    setIsActive(true);
    inputRef.current?.focus();
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      if (!isLoading && value.trim()) {
        onSubmit();
      }
    }
  };

  const containerVariants = {
    collapsed: {
      height: 68,
      boxShadow: "0 2px 8px 0 rgba(0,0,0,0.2)",
      transition: { type: "spring", stiffness: 120, damping: 18 },
    },
    expanded: {
      height: 128,
      boxShadow: "0 8px 32px 0 rgba(0,0,0,0.35)",
      transition: { type: "spring", stiffness: 120, damping: 18 },
    },
  };

  const placeholderContainerVariants = {
    initial: {},
    animate: { transition: { staggerChildren: 0.025 } },
    exit: { transition: { staggerChildren: 0.015, staggerDirection: -1 } },
  };

  const letterVariants = {
    initial: {
      opacity: 0,
      filter: "blur(12px)",
      y: 10,
    },
    animate: {
      opacity: 1,
      filter: "blur(0px)",
      y: 0,
      transition: {
        opacity: { duration: 0.25 },
        filter: { duration: 0.4 },
        y: { type: "spring", stiffness: 80, damping: 20 },
      },
    },
    exit: {
      opacity: 0,
      filter: "blur(12px)",
      y: -10,
      transition: {
        opacity: { duration: 0.2 },
        filter: { duration: 0.3 },
        y: { type: "spring", stiffness: 80, damping: 20 },
      },
    },
  };

  return (
    <div className="w-full" ref={wrapperRef}>
      <motion.div
        className="w-full"
        variants={containerVariants}
        animate={isActive || value ? "expanded" : "collapsed"}
        initial="collapsed"
        style={{ overflow: "hidden", borderRadius: 24, background: "hsl(var(--card))" }}
        onClick={handleActivate}
      >
        <div className="flex flex-col items-stretch w-full h-full">
          {/* Input Row */}
          <div className="flex items-center gap-2 p-3 rounded-full w-full">
            {/* Text Input & Placeholder */}
            <div className="relative flex-1">
              <input
                ref={inputRef}
                type="text"
                value={value}
                onChange={(e) => {
                  const v = e.target.value;
                  if (!maxLength || v.length <= maxLength) {
                    onChange(v);
                  }
                }}
                onFocus={handleActivate}
                onKeyDown={handleKeyDown}
                disabled={disabled}
                className="flex-1 border-0 outline-0 rounded-md py-2 text-base bg-transparent w-full font-normal text-foreground placeholder:text-transparent"
                style={{ position: "relative", zIndex: 1 }}
              />
              <div className="absolute left-0 top-0 w-full h-full pointer-events-none flex items-center px-3 py-2">
                <AnimatePresence mode="wait">
                  {showPlaceholder && !isActive && !value && (
                    <motion.span
                      key={placeholderIndex}
                      className="absolute left-0 top-1/2 -translate-y-1/2 text-muted-foreground select-none pointer-events-none"
                      style={{
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        zIndex: 0,
                      }}
                      variants={placeholderContainerVariants}
                      initial="initial"
                      animate="animate"
                      exit="exit"
                    >
                      {placeholders[placeholderIndex]
                        .split("")
                        .map((char, i) => (
                          <motion.span
                            key={i}
                            variants={letterVariants}
                            style={{ display: "inline-block" }}
                          >
                            {char === " " ? "\u00A0" : char}
                          </motion.span>
                        ))}
                    </motion.span>
                  )}
                </AnimatePresence>
              </div>
            </div>

            {showCharCount && maxLength && (
              <span className="text-xs text-muted-foreground whitespace-nowrap">
                {value.length}/{maxLength}
              </span>
            )}

            <button
              className={cn(
                "flex items-center gap-1 p-3 rounded-full font-medium justify-center transition-all",
                isLoading || !value.trim() || disabled
                  ? "bg-muted text-muted-foreground cursor-not-allowed"
                  : "bg-primary hover:bg-primary/90 text-primary-foreground"
              )}
              title="Send"
              type="button"
              tabIndex={-1}
              disabled={isLoading || !value.trim() || disabled}
              onClick={(e) => {
                e.stopPropagation();
                onSubmit();
              }}
            >
              {isLoading ? <Loader2 size={18} className="animate-spin" /> : <Send size={18} />}
            </button>
          </div>

          {/* Expanded Controls */}
          <motion.div
            className="w-full flex justify-start px-4 items-center text-sm"
            variants={{
              hidden: {
                opacity: 0,
                y: 20,
                pointerEvents: "none" as const,
                transition: { duration: 0.25 },
              },
              visible: {
                opacity: 1,
                y: 0,
                pointerEvents: "auto" as const,
                transition: { duration: 0.35, delay: 0.08 },
              },
            }}
            initial="hidden"
            animate={isActive || value ? "visible" : "hidden"}
            style={{ marginTop: 8 }}
          >
            <div className="flex gap-3 items-center">
              {/* Think Toggle */}
              {onThinkToggle && (
                <button
                  className={cn(
                    "flex items-center gap-1 px-4 py-2 rounded-full transition-all font-medium group text-sm",
                    thinkActive
                      ? "bg-primary/10 outline outline-primary/60 text-primary"
                      : "bg-muted text-muted-foreground hover:bg-muted/80"
                  )}
                  title="Think"
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    onThinkToggle();
                  }}
                >
                  <Lightbulb
                    className={cn(
                      "transition-all",
                      thinkActive ? "fill-yellow-400 text-yellow-400" : "group-hover:fill-yellow-400/30"
                    )}
                    size={18}
                  />
                  Think
                </button>
              )}

              {/* Deep Search Toggle */}
              {onDeepSearchToggle && (
                <motion.button
                  className={cn(
                    "flex items-center px-4 gap-1 py-2 rounded-full transition font-medium whitespace-nowrap overflow-hidden justify-start text-sm",
                    deepSearchActive
                      ? "bg-primary/10 outline outline-primary/60 text-primary"
                      : "bg-muted text-muted-foreground hover:bg-muted/80"
                  )}
                  title="Deep Search"
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    onDeepSearchToggle();
                  }}
                  initial={false}
                  animate={{
                    width: deepSearchActive ? 130 : 38,
                    paddingLeft: deepSearchActive ? 12 : 9,
                  }}
                >
                  <div className="flex-1">
                    <Globe size={18} />
                  </div>
                  <motion.span
                    className="pb-[2px]"
                    initial={false}
                    animate={{
                      opacity: deepSearchActive ? 1 : 0,
                    }}
                  >
                    Deep Search
                  </motion.span>
                </motion.button>
              )}
            </div>
          </motion.div>
        </div>
      </motion.div>
    </div>
  );
}
