"use client";

import { motion } from "framer-motion";
import Image from "next/image";
import { cn } from "@/lib/utils";

interface AriaLogoProps {
  size?: number;
  animate?: boolean;
  className?: string;
}

export function AriaLogo({ size = 40, animate = false, className }: AriaLogoProps) {
  const image = (
    <Image
      src="/aria-logo-icon.png"
      alt="ARIA Logo"
      width={size}
      height={size}
      className={cn("rounded-lg object-contain", className)}
      priority
    />
  );

  if (!animate) {
    return image;
  }

  return (
    <motion.div
      initial={{ scale: 0.8, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      transition={{ duration: 0.5, ease: "easeOut" }}
    >
      <motion.div
        animate={{
          scale: [1, 1.05, 1],
          rotate: [0, 2, -2, 0],
        }}
        transition={{
          duration: 3,
          repeat: Infinity,
          ease: "easeInOut",
        }}
      >
        {image}
      </motion.div>
    </motion.div>
  );
}
