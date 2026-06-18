"use client";

import { useState, useRef, useEffect, useCallback } from "react";
import { format, formatDistanceToNow } from "date-fns";
import {
  Send,
  Bot,
  User,
  AlertTriangle,
  FileWarning,
  Search,
  Lightbulb,
  Loader2,
  ArrowDown,
  Plus,
  Trash2,
  MessageSquare,
  ChevronLeft,
  Check,
  X,
  Shield,
  Zap,
  RotateCcw,
  Info,
  Square,
  ShieldAlert,
  Clock,
  Server,
  Globe,
} from "lucide-react";
import { aiAPI, type AssistantAction, type AssistantConversation } from "@/lib/api";
import { useSelectedAsset } from "@/lib/asset-context";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { cn } from "@/lib/utils";
import { severityClasses } from "@/lib/ui-status";
import { AIChatInput } from "@/components/ui/ai-chat-input";
import { useToast } from "@/hooks/use-toast";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";

interface Message {
  id: string;
  role: "user" | "assistant" | "action";
  content: string;
  actions?: AssistantAction[];
  isActionResult?: boolean;
  sources?: Record<string, any>[];
  recordCount?: number;
  timestamp: Date;
}

const exampleQuestions = [
  { icon: AlertTriangle, question: "What are the most critical alerts right now?" },
  { icon: FileWarning, question: "Summarize the current open incidents" },
  { icon: Search, question: "Are there any patterns in the recent SSH attacks?" },
  { icon: Lightbulb, question: "Recommend security improvements based on recent incidents" },
];

const MAX_INPUT_LENGTH = 2000;
const QUERY_TIMEOUT_MS = 25000;

const REQUIRES_CONFIRMATION = new Set([
  "approve_investigation",
  "decline_investigation",
  "execute_investigation",
  "archive_investigation",
]);

function useIdCounter() {
  const ref = useRef(0);
  return useCallback(() => {
    ref.current += 1;
    return `msg-${Date.now()}-${ref.current}`;
  }, []);
}

function severityBadgeVariant(severity?: string): "default" | "secondary" | "destructive" | "outline" {
  const s = (severity || "").toLowerCase();
  if (s === "critical") return "destructive";
  if (s === "high") return "destructive";
  if (s === "medium") return "secondary";
  if (s === "low") return "outline";
  return "default";
}

// Severity badge classes — delegates to the shared design-token scale so
// severity colors stay consistent with <SeverityBadge> across the app.
function severityColorClass(severity?: string): string {
  return severityClasses(severity);
}

function dedupeActions(actions: AssistantAction[]): AssistantAction[] {
  const seen = new Set<string>();
  return actions.filter((a) => {
    const idPart = a.params?.investigation_id || a.params?.action_id || a.params?.target_id || "";
    const key = idPart
      ? `${a.type}-${idPart}`
      : `${a.type}-${a.label}-${JSON.stringify(a.params)}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function stripMarkdown(text: string): string {
  return text
    .replace(/#{1,6}\s/g, "") // headings
    .replace(/\*\*(.*?)\*\*/g, "$1") // bold
    .replace(/__(.*?)__/g, "$1") // underline bold
    .replace(/\*(.*?)\*/g, "$1") // italic
    .replace(/_(.*?)_/g, "$1") // underline italic
    .replace(/`{1,3}(.*?)`{1,3}/g, "$1") // inline code
    .replace(/!\[.*?\]\(.*?\)/g, "") // images
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1") // links
    .replace(/^\s*[-*+]\s+/gm, "") // list bullets
    .replace(/^\s*\d+\.\s+/gm, "") // numbered lists
    .trim();
}

function dedupeSources(sources: Record<string, any>[]): Record<string, any>[] {
  const seen = new Set<string>();
  return sources.filter((s) => {
    const key =
      s.id ||
      `${s.type}-${s.title || s.incident_title || s.alert_name || s.host || ""}-${
        s.source || s.hostname || s.host || s.source_ip || ""
      }-${s.severity || ""}-${s.created_at || s.timestamp || ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function formatSourceTime(iso?: string): string {
  if (!iso) return "";
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    return formatDistanceToNow(d, { addSuffix: true });
  } catch {
    return iso;
  }
}

function StructuredSources({ sources }: { sources?: Record<string, any>[] }) {
  if (!sources || sources.length === 0) return null;

  const deduped = dedupeSources(sources);
  const alerts = deduped.filter((s) => s.type === "live_alert");
  const incidents = deduped.filter((s) => s.type === "live_incident");
  const investigations = deduped.filter((s) => s.type === "active_investigation" || s.type === "investigation");
  const ipsEvents = deduped.filter((s) => s.type === "ips_event");

  return (
    <div className="space-y-3 mt-3">
      {alerts.length > 0 && (
        <div className="space-y-2">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Alerts</h4>
          {alerts.map((alert, idx) => (
            <div
              key={`alert-${idx}`}
              className="rounded-lg border bg-card p-3 shadow-sm"
            >
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <p className="text-sm font-medium leading-tight">{alert.title || "Untitled Alert"}</p>
                  <div className="flex flex-wrap items-center gap-2 mt-1.5">
                    <Badge
                      variant="outline"
                      className={cn("text-xs px-1.5 py-0", severityColorClass(alert.severity))}
                    >
                      {(alert.severity || "unknown").toUpperCase()}
                    </Badge>
                    <span className="flex items-center gap-1 text-xs text-muted-foreground">
                      <Server className="h-3 w-3" />
                      {alert.source || "unknown"}
                      {alert.hostname && alert.hostname !== "unknown" ? ` — ${alert.hostname}` : ""}
                    </span>
                    {alert.source_ip && (
                      <span className="flex items-center gap-1 text-xs text-muted-foreground">
                        <Globe className="h-3 w-3" />
                        {alert.source_ip}
                      </span>
                    )}
                  </div>
                </div>
              </div>
              {alert.description && (
                <p className="text-xs text-muted-foreground mt-2 line-clamp-2">{stripMarkdown(alert.description)}</p>
              )}
              <div className="flex items-center justify-between mt-2">
                <span className="flex items-center gap-1 text-xs text-muted-foreground">
                  <Clock className="h-3 w-3" />
                  {formatSourceTime(alert.created_at)}
                </span>
                <span className="text-xs text-muted-foreground italic">
                  {alert.severity === "critical" || alert.severity === "high"
                    ? "Escalate or investigate immediately"
                    : "Monitor and correlate with related events"}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}

      {incidents.length > 0 && (
        <div className="space-y-2">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Incidents</h4>
          {incidents.map((inc, idx) => (
            <div
              key={`inc-${idx}`}
              className="rounded-lg border bg-card p-3 shadow-sm"
            >
              <div className="flex items-center justify-between gap-2">
                <p className="text-sm font-medium">{inc.title || "Untitled Incident"}</p>
                <Badge
                  variant="outline"
                  className={cn("text-xs px-1.5 py-0", severityColorClass(inc.severity))}
                >
                  {(inc.severity || "unknown").toUpperCase()}
                </Badge>
              </div>
              <div className="flex flex-wrap items-center gap-2 mt-1.5 text-xs text-muted-foreground">
                <span>Status: {inc.status || "unknown"}</span>
                <span>•</span>
                <span>{inc.alert_count || 0} alerts</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {investigations.length > 0 && (
        <div className="space-y-2">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Investigations</h4>
          {investigations.map((inv, idx) => (
            <div
              key={`inv-${idx}`}
              className="rounded-lg border bg-card p-3 shadow-sm"
            >
              <div className="flex items-center justify-between gap-2">
                <p className="text-sm font-medium">{inv.incident_title || "Untitled Investigation"}</p>
                <Badge
                  variant="outline"
                  className={cn("text-xs px-1.5 py-0", severityColorClass(inv.severity || inv.incident_severity))}
                >
                  {(inv.severity || inv.incident_severity || "unknown").toUpperCase()}
                </Badge>
              </div>
              <div className="text-xs text-muted-foreground mt-1">Status: {inv.status || "unknown"}</div>
              {inv.ai_summary && (
                <p className="text-xs text-muted-foreground mt-1.5 line-clamp-2">{stripMarkdown(inv.ai_summary)}</p>
              )}
            </div>
          ))}
        </div>
      )}

      {ipsEvents.length > 0 && (
        <div className="space-y-2">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">IPS Events</h4>
          {ipsEvents.map((evt, idx) => (
            <div
              key={`ips-${idx}`}
              className="rounded-lg border bg-card p-3 shadow-sm"
            >
              <div className="flex items-center justify-between gap-2">
                <p className="text-sm font-medium">{evt.alert_name || "Unknown Event"}</p>
                <Badge
                  variant="outline"
                  className={cn("text-xs px-1.5 py-0", severityColorClass(evt.severity))}
                >
                  {(evt.severity || "unknown").toUpperCase()}
                </Badge>
              </div>
              <div className="text-xs text-muted-foreground mt-1">
                {evt.source_ip || "unknown"} {evt.source_country ? `(${evt.source_country})` : ""} → {evt.destination_ip || "unknown"} {evt.destination_country ? `(${evt.destination_country})` : ""}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function getLoadingText(question: string): string {
  const q = question.toLowerCase();
  if (q.includes("alert")) return "Checking current alerts...";
  if (q.includes("incident")) return "Reviewing incidents...";
  if (q.includes("investigation")) return "Reviewing investigations...";
  if (q.includes("performance") || q.includes("cpu") || q.includes("ram") || q.includes("memory") || q.includes("disk")) {
    return "Checking system performance...";
  }
  return "Preparing answer...";
}

function withTimeout<T>(promise: Promise<T>, ms: number, signal?: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Request timed out. Please try again.")), ms);
    promise
      .then((val) => {
        clearTimeout(timer);
        resolve(val);
      })
      .catch((err) => {
        clearTimeout(timer);
        reject(err);
      });
    if (signal) {
      signal.addEventListener("abort", () => {
        clearTimeout(timer);
        reject(new DOMException("Aborted", "AbortError"));
      });
    }
  });
}

export default function AssistantPage() {
  const { toast } = useToast();
  const { selectedAssetId } = useSelectedAsset();
  const nextId = useIdCounter();
  const [conversations, setConversations] = useState<AssistantConversation[]>([]);
  const [activeConversationId, setActiveConversationId] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([
    {
      id: "welcome",
      role: "assistant",
      content:
        "Hello! I'm ARIA, your AI security assistant. I can analyze threats, investigate incidents, review system performance, and even help you take action on investigations. How can I assist you today?",
      timestamp: new Date(),
    },
  ]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [showScrollButton, setShowScrollButton] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [isLoadingConversations, setIsLoadingConversations] = useState(false);
  const pendingQuestionRef = useRef("");

  // Confirmation modal state
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [pendingAction, setPendingAction] = useState<AssistantAction | null>(null);
  const [executingAction, setExecutingAction] = useState(false);

  // Delete conversation confirmation
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [conversationToDelete, setConversationToDelete] = useState<string | null>(null);


  const assistantPlaceholders = [
    "Your infrastructure deserves better observability",
    "What are the most critical alerts right now?",
    "Summarize open incidents across all assets...",
    "Analyze threat patterns in recent SSH attacks",
    "Recommend security improvements",
    "Check system performance across all hosts",
  ];

  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const justSentRef = useRef(false);
  const abortRef = useRef<AbortController | null>(null);
  const actionAbortRef = useRef<AbortController | null>(null);

  // Load conversations on mount
  useEffect(() => {
    loadConversations();
    return () => {
      abortRef.current?.abort();
      actionAbortRef.current?.abort();
    };
  }, []);

  const loadConversations = useCallback(async () => {
    setIsLoadingConversations(true);
    try {
      const res = await aiAPI.listConversations(50);
      setConversations(res.conversations);
    } catch (e: any) {
      if (e?.name !== "AbortError") {
        // silent fail for background loads
      }
    } finally {
      setIsLoadingConversations(false);
    }
  }, []);

  const startNewConversation = useCallback(async () => {
    try {
      const conv = await aiAPI.createConversation({ title: "New Conversation" });
      setActiveConversationId(conv.id);
      setMessages([
        {
          id: "welcome",
          role: "assistant",
          content:
            "Hello! I'm ARIA, your AI security assistant. I can analyze threats, investigate incidents, review system performance, and even help you take action on investigations. How can I assist you today?",
          timestamp: new Date(),
        },
      ]);
      setConversations((prev) => [conv, ...prev]);
      setInput("");
      inputRef.current?.focus();
    } catch (e: any) {
      toast({ title: "Failed to create conversation", description: e?.message, variant: "destructive" });
    }
  }, [toast]);

  const switchConversation = useCallback(async (id: string) => {
    setActiveConversationId(id);
    setMessages([]);
    setIsLoading(true);
    abortRef.current?.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    try {
      const conv = await aiAPI.getConversation(id, ctrl.signal);
      const loadedMessages: Message[] = conv.messages.map((m) => ({
        id: m.id,
        role: m.role,
        content: m.content,
        actions: m.actions || undefined,
        sources: m.sources || undefined,
        timestamp: new Date(m.created_at),
      }));
      setMessages(loadedMessages);
    } catch (e: any) {
      if (e?.name !== "AbortError") {
        toast({ title: "Failed to load conversation", description: e?.message, variant: "destructive" });
      }
    } finally {
      setIsLoading(false);
      setTimeout(() => scrollToBottom(), 0);
    }
  }, [toast]);

  const promptDeleteConversation = useCallback((id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setConversationToDelete(id);
    setDeleteDialogOpen(true);
  }, []);

  const handleConfirmDelete = useCallback(async () => {
    if (!conversationToDelete) return;
    try {
      await aiAPI.deleteConversation(conversationToDelete);
      setConversations((prev) => prev.filter((c) => c.id !== conversationToDelete));
      if (activeConversationId === conversationToDelete) {
        setActiveConversationId(null);
        setMessages([
          {
            id: "welcome",
            role: "assistant",
            content:
              "Hello! I'm ARIA, your AI security assistant. I can analyze threats, investigate incidents, review system performance, and even help you take action on investigations. How can I assist you today?",
            timestamp: new Date(),
          },
        ]);
      }
    } catch (err: any) {
      toast({ title: "Failed to delete conversation", description: err?.message, variant: "destructive" });
    } finally {
      setDeleteDialogOpen(false);
      setConversationToDelete(null);
    }
  }, [activeConversationId, conversationToDelete, toast]);

  const scrollToBottom = (behavior: ScrollBehavior = "auto") => {
    const el = scrollRef.current;
    if (!el) return;
    if (behavior === "smooth") {
      el.scrollTo({ top: el.scrollHeight, behavior: "smooth" });
    } else {
      el.scrollTop = el.scrollHeight;
    }
  };

  const checkScrollPosition = () => {
    const el = scrollRef.current;
    if (!el) return;
    const isNearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
    setShowScrollButton(!isNearBottom);
  };

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    el.addEventListener("scroll", checkScrollPosition, { passive: true });
    checkScrollPosition();
    return () => el.removeEventListener("scroll", checkScrollPosition);
  }, []);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    if (justSentRef.current) {
      justSentRef.current = false;
      scrollToBottom();
      setShowScrollButton(false);
      return;
    }
    const isNearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
    if (isNearBottom) {
      scrollToBottom();
      setShowScrollButton(false);
    }
  }, [messages]);

  const handleSubmit = async (e?: React.FormEvent) => {
    e?.preventDefault();
    if (!input.trim() || isLoading) return;

    // Cancel any in-flight query
    abortRef.current?.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;

    // Auto-create conversation on first user message if none active
    let convId = activeConversationId;
    if (!convId) {
      try {
        const conv = await aiAPI.createConversation({ title: input.trim().slice(0, 60) });
        convId = conv.id;
        setActiveConversationId(conv.id);
        setConversations((prev) => [conv, ...prev]);
      } catch (err: any) {
        toast({ title: "Failed to start conversation", description: err?.message, variant: "destructive" });
        return;
      }
    }

    const userMessage: Message = {
      id: nextId(),
      role: "user",
      content: input.trim(),
      timestamp: new Date(),
    };

    justSentRef.current = true;
    pendingQuestionRef.current = userMessage.content;
    setMessages((prev) => [...prev, userMessage]);
    setInput("");
    setIsLoading(true);
    setTimeout(() => {
      scrollToBottom();
      setShowScrollButton(false);
    }, 0);

    try {
      const response = await withTimeout(
        aiAPI.query(
          {
            question: userMessage.content,
            conversation_id: convId || undefined,
            asset_id: selectedAssetId || undefined,
          },
          ctrl.signal
        ),
        QUERY_TIMEOUT_MS
      );

      const assistantMessage: Message = {
        id: nextId(),
        role: "assistant",
        content: response.answer || "ARIA did not return an answer.",
        actions: response.actions,
        sources: response.sources,
        recordCount: response.record_count,
        timestamp: new Date(),
      };

      setMessages((prev) => [...prev, assistantMessage]);
      loadConversations();
    } catch (error: any) {
      if (error?.name === "AbortError") {
        setMessages((prev) => prev.filter((m) => m.id !== userMessage.id));
        return;
      }
      const isTimeout = error?.message?.includes("timed out");
      const errorMessage: Message = {
        id: nextId(),
        role: "assistant",
        content: isTimeout
          ? "ARIA took too long to respond. Please try again."
          : error instanceof Error
            ? `I apologize, but I encountered an error: ${error.message}`
            : "I apologize, but I encountered an error. Please try again.",
        timestamp: new Date(),
      };
      setMessages((prev) => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
      abortRef.current = null;
      pendingQuestionRef.current = "";
    }
  };

  const handleStop = () => {
    abortRef.current?.abort();
    abortRef.current = null;
    setIsLoading(false);
  };

  const handleRetry = async (failedMessageIndex: number) => {
    const prevUserIndex = failedMessageIndex - 1;
    if (prevUserIndex < 0 || messages[prevUserIndex].role !== "user") return;
    const question = messages[prevUserIndex].content;
    const convId = activeConversationId;
    if (!convId) return;

    setMessages((prev) => prev.slice(0, failedMessageIndex));
    setIsLoading(true);

    abortRef.current?.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;

    try {
      const response = await withTimeout(
        aiAPI.query({ question, conversation_id: convId, asset_id: selectedAssetId || undefined }, ctrl.signal),
        QUERY_TIMEOUT_MS
      );
      const assistantMessage: Message = {
        id: nextId(),
        role: "assistant",
        content: response.answer || "ARIA did not return an answer.",
        actions: response.actions,
        sources: response.sources,
        recordCount: response.record_count,
        timestamp: new Date(),
      };
      setMessages((prev) => [...prev, assistantMessage]);
      loadConversations();
    } catch (error: any) {
      if (error?.name === "AbortError") return;
      const isTimeout = error?.message?.includes("timed out");
      const errorMessage: Message = {
        id: nextId(),
        role: "assistant",
        content: isTimeout
          ? "ARIA took too long to respond. Please try again."
          : error instanceof Error
            ? `I apologize, but I encountered an error: ${error.message}`
            : "I apologize, but I encountered an error. Please try again.",
        timestamp: new Date(),
      };
      setMessages((prev) => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
      abortRef.current = null;
      pendingQuestionRef.current = "";
    }
  };

  // ── Action handling with confirmation modal ───────────────────────────────

  const onActionButtonClick = (action: AssistantAction) => {
    if (REQUIRES_CONFIRMATION.has(action.type)) {
      setPendingAction(action);
      setConfirmOpen(true);
    } else {
      runAction(action);
    }
  };

  const runAction = async (action: AssistantAction) => {
    if (executingAction) return;
    setExecutingAction(true);
    setIsLoading(true);

    const actionMsg: Message = {
      id: nextId(),
      role: "action",
      content: `Executing ${action.label}...`,
      timestamp: new Date(),
    };
    setMessages((prev) => [...prev, actionMsg]);

    actionAbortRef.current?.abort();
    const ctrl = new AbortController();
    actionAbortRef.current = ctrl;

    try {
      const result = await aiAPI.executeAction(
        {
          action_type: action.type,
          params: action.params,
        },
        ctrl.signal
      );

      const resultMsg: Message = {
        id: nextId(),
        role: "assistant",
        content: result.success
          ? `✅ **${action.label}** completed successfully.` +
            (result.data?.message ? ` ${result.data.message}` : "")
          : `❌ **${action.label}** failed: ${result.error || "Unknown error"}`,
        isActionResult: true,
        timestamp: new Date(),
      };
      setMessages((prev) => [...prev.slice(0, -1), resultMsg]);
    } catch (error: any) {
      if (error?.name === "AbortError") {
        setMessages((prev) => prev.slice(0, -1));
        return;
      }

      let content: string;
      if (error?.message?.includes("401") || error?.message?.includes("Unauthorized") || error?.message?.includes("Authentication required")) {
        content = `🔒 **${action.label}** could not be executed. You must be signed in.`;
      } else if (error?.message?.includes("403") || error?.message?.includes("Forbidden") || error?.message?.includes("Admin privileges required")) {
        content = `🚫 **${action.label}** could not be executed. You do not have permission to perform this action.`;
      } else {
        content = `❌ **${action.label}** failed. Please retry.`;
      }

      const resultMsg: Message = {
        id: nextId(),
        role: "assistant",
        content,
        isActionResult: true,
        timestamp: new Date(),
      };
      setMessages((prev) => [...prev.slice(0, -1), resultMsg]);
    } finally {
      setIsLoading(false);
      setExecutingAction(false);
      actionAbortRef.current = null;
    }
  };

  const handleConfirmAction = () => {
    if (pendingAction) {
      setConfirmOpen(false);
      runAction(pendingAction);
      setPendingAction(null);
    }
  };

  const handleCancelAction = () => {
    setConfirmOpen(false);
    setPendingAction(null);
  };

  const handleExampleClick = (question: string) => {
    setInput(question);
    inputRef.current?.focus();
  };

  const actionIcon = (type: string) => {
    if (type.includes("approve")) return Check;
    if (type.includes("decline")) return X;
    if (type.includes("execute")) return Zap;
    if (type.includes("archive")) return Shield;
    return Shield;
  };

  const isErrorMessage = (m: Message) =>
    m.role === "assistant" &&
    !m.isActionResult &&
    (m.content.startsWith("I apologize, but I encountered an error") ||
      m.content.startsWith("ARIA took too long to respond") ||
      m.content.startsWith("❌"));

  const confirmTitle = pendingAction
    ? `Confirm ${pendingAction.label}`
    : "Confirm Action";

  const confirmDescription = pendingAction
    ? `You are about to ${pendingAction.type.replace(/_/g, " ")}${pendingAction.params?.investigation_id ? ` for investigation ${pendingAction.params.investigation_id}` : ""}. This action may affect running systems. Are you sure?`
    : "Are you sure you want to perform this action?";

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden">
      <PageHeader
        title="AI Security Assistant"
        description="Context-aware conversations with state and actions"
        actions={
          <Button variant="outline" size="sm" onClick={startNewConversation}>
            <Plus className="h-4 w-4 mr-1" />
            New Chat
          </Button>
        }
      />

      <div className="flex flex-1 overflow-hidden p-6 gap-4 min-h-0">
        {/* Sidebar */}
        <Card
          className={cn(
            "flex flex-col transition-all duration-300 overflow-hidden shrink-0 min-h-0",
            sidebarOpen ? "w-60 opacity-100" : "w-0 opacity-0 p-0 border-0"
          )}
        >
          <div className="flex items-center justify-between p-2.5 border-b">
            <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">History</span>
            <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setSidebarOpen(false)}>
              <ChevronLeft className="h-4 w-4" />
            </Button>
          </div>
          <div className="flex-1 overflow-y-auto p-1.5 space-y-0.5 min-h-0">
            {isLoadingConversations ? (
              <div className="text-xs text-muted-foreground p-2">Loading...</div>
            ) : (
              conversations.map((conv) => (
                <div
                  key={conv.id}
                  onClick={() => switchConversation(conv.id)}
                  className={cn(
                    "group flex items-center justify-between px-2.5 py-1.5 rounded-md cursor-pointer text-sm border-l-2 transition-colors",
                    activeConversationId === conv.id
                      ? "bg-primary/10 border-l-primary text-primary"
                      : "border-l-transparent hover:bg-muted"
                  )}
                >
                  <div className="flex-1 min-w-0">
                    <div className="truncate text-sm leading-tight">{conv.title}</div>
                    <div className="text-[10px] text-muted-foreground mt-0.5">
                      {conv.message_count ?? 0} messages · {conv.updated_at && !isNaN(new Date(conv.updated_at).getTime()) ? formatDistanceToNow(new Date(conv.updated_at), { addSuffix: true }) : "—"}
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-5 w-5 opacity-0 group-hover:opacity-100 transition-opacity shrink-0 ml-1"
                    onClick={(e) => promptDeleteConversation(conv.id, e)}
                  >
                    <Trash2 className="h-3 w-3" />
                  </Button>
                </div>
              ))
            )}
          </div>
        </Card>

        {/* Main chat area */}
        <Card className="flex flex-1 flex-col overflow-hidden min-h-0">
          {!sidebarOpen && (
            <div className="absolute top-20 left-6 z-10">
              <Button variant="outline" size="icon" className="h-8 w-8" onClick={() => setSidebarOpen(true)}>
                <MessageSquare className="h-4 w-4" />
              </Button>
            </div>
          )}

          {/* Messages */}
          <div className="flex-1 relative min-h-0">
            <div ref={scrollRef} className="h-full overflow-y-auto p-4">
              <div className="space-y-5">
                {messages.map((message, idx) => (
                  <div key={message.id} className={cn("flex gap-3", message.role === "user" && "justify-end")}>
                    {message.role === "assistant" && (
                      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                        <Bot className="h-4 w-4 text-primary" />
                      </div>
                    )}
                    {message.role === "action" && (
                      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-orange-500/10">
                        <Zap className="h-4 w-4 text-orange-500" />
                      </div>
                    )}
                    <div
                      className={cn(
                        "max-w-[92%] space-y-2",
                        message.role === "user" && "text-right"
                      )}
                    >
                      <div
                        className={cn(
                          "inline-block rounded-lg px-4 py-2.5",
                          message.role === "user"
                            ? "bg-primary text-primary-foreground"
                            : message.isActionResult
                            ? "bg-muted border border-border"
                            : isErrorMessage(message)
                            ? "bg-destructive/10 border border-destructive/20"
                            : "bg-muted"
                        )}
                      >
                        <div className="whitespace-pre-wrap text-sm prose prose-sm dark:prose-invert max-w-none">
                          {message.content.split("\n").map((line, i) => (
                            <p key={i} className={cn("mb-1 last:mb-0", !line.trim() && "h-1")}>
                              {line}
                            </p>
                          ))}
                        </div>
                      </div>

                      {/* Structured source cards */}
                      {message.sources && message.sources.length > 0 && (
                        <StructuredSources sources={message.sources} />
                      )}

                      {/* Source summary */}
                      {message.recordCount !== undefined && message.recordCount > 0 && (
                        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                          <Info className="h-3 w-3" />
                          <span>Based on {message.recordCount} system record{message.recordCount === 1 ? "" : "s"}</span>
                        </div>
                      )}

                      {/* Action buttons — deduplicated */}
                      {message.actions && message.actions.length > 0 && (
                        <div className="flex flex-wrap gap-2 pt-1">
                          {dedupeActions(message.actions).map((action, aidx) => {
                            const Icon = actionIcon(action.type);
                            const key = `${action.type}-${action.params?.investigation_id || aidx}`;
                            return (
                              <Button
                                key={key}
                                variant="secondary"
                                size="sm"
                                className="h-8 text-xs"
                                disabled={isLoading || executingAction}
                                onClick={() => onActionButtonClick(action)}
                              >
                                <Icon className="h-3.5 w-3.5 mr-1" />
                                {action.label}
                              </Button>
                            );
                          })}
                        </div>
                      )}

                      {/* Retry for errors */}
                      {isErrorMessage(message) && (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 text-xs gap-1 text-muted-foreground"
                          disabled={isLoading}
                          onClick={() => handleRetry(idx)}
                        >
                          <RotateCcw className="h-3 w-3" />
                          Retry
                        </Button>
                      )}

                      <p className="text-xs text-muted-foreground">
                        {format(message.timestamp, "h:mm a")}
                      </p>
                    </div>
                    {message.role === "user" && (
                      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-secondary">
                        <User className="h-4 w-4 text-secondary-foreground" />
                      </div>
                    )}
                  </div>
                ))}

                {isLoading && (
                  <div className="flex gap-3">
                    <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                      <Bot className="h-4 w-4 text-primary" />
                    </div>
                    <div className="flex items-center gap-3 rounded-lg bg-muted px-4 py-2.5">
                      <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
                      <span className="text-sm text-muted-foreground">{getLoadingText(pendingQuestionRef.current)}</span>
                      <button
                        onClick={handleStop}
                        className="ml-1 inline-flex h-5 w-5 items-center justify-center rounded text-muted-foreground hover:text-foreground hover:bg-muted-foreground/10 transition-colors"
                        title="Cancel"
                      >
                        <X className="h-3 w-3" />
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {showScrollButton && (
              <Button
                variant="secondary"
                size="sm"
                className="absolute bottom-4 left-1/2 -translate-x-1/2 shadow-md z-10"
                onClick={() => {
                  scrollToBottom("smooth");
                  setShowScrollButton(false);
                }}
              >
                <ArrowDown className="h-4 w-4 mr-1" />
                Scroll to bottom
              </Button>
            )}
          </div>

          {/* Example Questions */}
          {messages.length === 1 && (
            <div className="border-t bg-muted/30 p-5">
              <p className="mb-4 text-sm font-medium text-foreground">Try asking</p>
              <div className="grid gap-3 sm:grid-cols-2">
                {exampleQuestions.map((example, index) => (
                  <button
                    key={index}
                    className="flex items-start gap-3 rounded-xl border bg-card p-3 text-left hover:bg-accent/50 hover:border-primary/30 transition-colors group"
                    onClick={() => handleExampleClick(example.question)}
                  >
                    <div className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary/10 group-hover:bg-primary/20 transition-colors">
                      <example.icon className="h-4 w-4 text-primary" />
                    </div>
                    <span className="text-sm leading-snug text-foreground/90">{example.question}</span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Input */}
          <div className="border-t bg-background/50 backdrop-blur p-4">
            <AIChatInput
              value={input}
              onChange={setInput}
              onSubmit={handleSubmit}
              placeholder="Your infrastructure deserves better observability"
              placeholders={assistantPlaceholders}
              disabled={isLoading}
              isLoading={isLoading}
              maxLength={MAX_INPUT_LENGTH}
              showCharCount

            />
          </div>
        </Card>
      </div>

      {/* Delete Conversation Dialog */}
      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Conversation</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete this conversation? This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => { setDeleteDialogOpen(false); setConversationToDelete(null); }}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={handleConfirmDelete}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Confirmation Modal */}
      <AlertDialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-destructive" />
              {confirmTitle}
            </AlertDialogTitle>
            <AlertDialogDescription>{confirmDescription}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={handleCancelAction} disabled={executingAction}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={handleConfirmAction}
              disabled={executingAction}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {executingAction ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Executing...
                </>
              ) : (
                "Confirm"
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
