"use client";

import { useEffect, useState, useRef } from "react";
import { cn } from "@/lib/utils";

interface AnimatedCounterProps {
  value: number;
  duration?: number;
  className?: string;
  prefix?: string;
  suffix?: string;
  decimals?: number;
}

export function AnimatedCounter({
  value,
  duration = 1000,
  className,
  prefix = "",
  suffix = "",
  decimals = 0,
}: AnimatedCounterProps) {
  const [displayValue, setDisplayValue] = useState(0);
  const previousValueRef = useRef(0);
  const animationRef = useRef<number | undefined>(undefined);
  const displayValueRef = useRef(0);

  useEffect(() => {
    const startValue = previousValueRef.current;
    const endValue = value;
    const startTime = performance.now();

    const animate = (currentTime: number) => {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      
      // Easing function (ease-out-cubic)
      const easeProgress = 1 - Math.pow(1 - progress, 3);
      
      const currentValue = startValue + (endValue - startValue) * easeProgress;
      displayValueRef.current = currentValue;
      setDisplayValue(currentValue);

      if (progress < 1) {
        animationRef.current = requestAnimationFrame(animate);
      } else {
        previousValueRef.current = endValue;
      }
    };

    animationRef.current = requestAnimationFrame(animate);

    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
        previousValueRef.current = displayValueRef.current;
      }
    };
  }, [value, duration]);

  const formattedValue = decimals > 0 
    ? displayValue.toFixed(decimals)
    : Math.round(displayValue).toLocaleString();

  return (
    <span className={cn("number-ticker tabular-nums", className)}>
      {prefix}{formattedValue}{suffix}
    </span>
  );
}

interface AnimatedPercentageProps {
  value: number;
  size?: "sm" | "md" | "lg";
  showLabel?: boolean;
  color?: "primary" | "success" | "warning" | "destructive";
  className?: string;
}

export function AnimatedPercentage({
  value,
  size = "md",
  showLabel = true,
  color = "primary",
  className,
}: AnimatedPercentageProps) {
  const [animatedValue, setAnimatedValue] = useState(0);

  useEffect(() => {
    const timer = setTimeout(() => setAnimatedValue(value), 100);
    return () => clearTimeout(timer);
  }, [value]);

  const sizeClasses = {
    sm: "h-1.5",
    md: "h-2",
    lg: "h-3",
  };

  const colorClasses = {
    primary: "bg-primary",
    success: "bg-success",
    warning: "bg-warning",
    destructive: "bg-destructive",
  };

  return (
    <div className={cn("space-y-1.5", className)}>
      {showLabel && (
        <div className="flex items-center justify-between text-sm">
          <span className="text-muted-foreground">Progress</span>
          <AnimatedCounter value={value} suffix="%" decimals={1} />
        </div>
      )}
      <div className={cn("w-full overflow-hidden rounded-full bg-muted", sizeClasses[size])}>
        <div
          className={cn(
            "h-full rounded-full transition-all duration-1000 ease-out progress-animated",
            colorClasses[color]
          )}
          style={{ width: `${animatedValue}%` }}
        />
      </div>
    </div>
  );
}
