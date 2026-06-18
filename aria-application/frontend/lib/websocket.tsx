"use client";

import { createContext, useContext, useEffect, useRef, useState, useCallback, type ReactNode } from "react";

const WS_URL = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8001/ws";

export type WSEventType =
  | "investigation_updated"
  | "incident_created"
  | "performance_alert"
  | "system_health";

export interface WSMessage extends Record<string, unknown> {
  type: WSEventType;
  timestamp: string;
}

interface WebSocketContextValue {
  isConnected: boolean;
  lastMessage: WSMessage | null;
  subscribe: (eventType: WSEventType, callback: (data: WSMessage) => void) => () => void;
  sendMessage: (message: Record<string, unknown>) => void;
}

const WebSocketContext = createContext<WebSocketContextValue | null>(null);

export function WebSocketProvider({ children }: { children: ReactNode }) {
  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<WSMessage | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const subscribersRef = useRef<Map<WSEventType, Set<(data: WSMessage) => void>>>(new Map());
  const reconnectAttemptsRef = useRef(0);
  const MAX_RECONNECT_LOGS = 3;

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    try {
      const ws = new WebSocket(WS_URL);

      ws.onopen = () => {
        setIsConnected(true);
        reconnectAttemptsRef.current = 0;
        console.log("[WebSocket] Connected to", WS_URL);
      };

      ws.onclose = () => {
        setIsConnected(false);
        reconnectAttemptsRef.current++;
        if (reconnectAttemptsRef.current <= MAX_RECONNECT_LOGS) {
          console.log(`[WebSocket] Disconnected, reconnecting... (${reconnectAttemptsRef.current}/${MAX_RECONNECT_LOGS})`);
        }
        // Use exponential backoff with max of 30s
        const delay = Math.min(3000 * Math.pow(1.5, reconnectAttemptsRef.current - 1), 30000);
        reconnectTimeoutRef.current = setTimeout(connect, delay);
      };

      ws.onerror = () => {
        // Silently handle errors - onclose will handle reconnection
      };

      ws.onmessage = (event) => {
        try {
          const message: WSMessage = JSON.parse(event.data);
          setLastMessage(message);

          const subscribers = subscribersRef.current.get(message.type);
          if (subscribers) {
            subscribers.forEach((callback) => callback(message));
          }
        } catch (err) {
          console.error("[WebSocket] Parse error:", err);
        }
      };

      wsRef.current = ws;
    } catch (err) {
      console.error("[WebSocket] Connection error:", err);
      reconnectTimeoutRef.current = setTimeout(connect, 3000);
    }
  }, []);

  useEffect(() => {
    connect();

    return () => {
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      wsRef.current?.close();
    };
  }, [connect]);

  const subscribe = useCallback((eventType: WSEventType, callback: (data: WSMessage) => void) => {
    if (!subscribersRef.current.has(eventType)) {
      subscribersRef.current.set(eventType, new Set());
    }
    subscribersRef.current.get(eventType)!.add(callback);

    return () => {
      subscribersRef.current.get(eventType)?.delete(callback);
    };
  }, []);

  const sendMessage = useCallback((message: Record<string, unknown>) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(message));
    }
  }, []);

  return (
    <WebSocketContext.Provider value={{ isConnected, lastMessage, subscribe, sendMessage }}>
      {children}
    </WebSocketContext.Provider>
  );
}

export function useWebSocket() {
  const context = useContext(WebSocketContext);
  if (!context) {
    throw new Error("useWebSocket must be used within a WebSocketProvider");
  }
  return context;
}

export function useWSSubscription(eventType: WSEventType, callback: (data: WSMessage) => void) {
  const { subscribe } = useWebSocket();

  useEffect(() => {
    return subscribe(eventType, callback);
  }, [eventType, callback, subscribe]);
}
