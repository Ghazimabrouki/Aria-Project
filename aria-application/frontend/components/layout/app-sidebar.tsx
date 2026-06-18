"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  AlertTriangle,
  FileWarning,
  Search,
  Archive,
  Activity,
  Bot,
  Shield,
  ShieldCheck,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  Moon,
  Sun,
  Monitor,
  Globe,
  Terminal,
  HardDrive,
  Settings,
  Server,
  Menu,
  X,
} from "lucide-react";
import Image from "next/image";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { useTheme } from "@/components/theme-provider";
import { useState, useEffect } from "react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Sheet, SheetContent, SheetTrigger, SheetTitle } from "@/components/ui/sheet";
import { useWebSocket } from "@/lib/websocket";
import { useSelectedAsset } from "@/lib/asset-context";
import { useAuth } from "@/lib/auth-context";
import { useIsMobile } from "@/hooks/use-mobile";

const APP_BRAND = process.env.NEXT_PUBLIC_APP_BRAND || "ARIA";
const APP_SUBTITLE = process.env.NEXT_PUBLIC_APP_SUBTITLE || "Security Operations Platform";
const APP_LICENSEE = process.env.NEXT_PUBLIC_APP_LICENSEE || "";

type NavItem = { name: string; href: string; icon: React.ElementType };
type NavSection = { label: string; items: NavItem[] };

const navigationSections: NavSection[] = [
  {
    label: "Overview",
    items: [
      { name: "Dashboard", href: "/", icon: LayoutDashboard },
      { name: "Search", href: "/search", icon: Search },
    ],
  },
  {
    label: "Security Operations",
    items: [
      { name: "Alerts", href: "/alerts", icon: AlertTriangle },
      { name: "Incidents", href: "/incidents", icon: FileWarning },
      { name: "Investigations", href: "/investigations", icon: Shield },
      { name: "IPS Map", href: "/ips", icon: Globe },
      { name: "Whitelist", href: "/whitelist", icon: ShieldCheck },
    ],
  },
  {
    label: "Infrastructure & Performance",
    items: [
      { name: "Performance", href: "/metrics", icon: Activity },
      { name: "Infrastructure", href: "/infrastructure/investigations", icon: HardDrive },
    ],
  },
  {
    label: "Runtime Security",
    items: [
      { name: "Runtime Security", href: "/runtime/investigations", icon: ShieldCheck },
    ],
  },
  {
    label: "AI Intelligence",
    items: [
      { name: "AI Assistant", href: "/assistant", icon: Bot },
      { name: "AI Operator", href: "/operator", icon: Terminal },
    ],
  },
  {
    label: "System Management",
    items: [
      { name: "Archives", href: "/archives", icon: Archive },
      { name: "Settings", href: "/settings", icon: Settings },
    ],
  },
];

function AssetSelector({ collapsed }: { collapsed: boolean }) {
  const { selectedAssetId, setSelectedAssetId, assets, isLoading } = useSelectedAsset();
  const { user } = useAuth();

  // Server users cannot change asset — it's locked to their account
  if (user?.role === "server_user") {
    if (isLoading) {
      return (
        <div className={cn("flex items-center gap-3 rounded-lg px-3 py-2 text-sm", collapsed && "justify-center")}>
          <Server className="h-4 w-4 text-muted-foreground" />
          {!collapsed && <span className="text-muted-foreground">Loading...</span>}
        </div>
      );
    }
    const lockedAsset = assets.find((a) => a.asset_id === user.asset_id);
    return (
      <div className={cn("flex items-center gap-3 rounded-lg px-3 py-2 text-sm", collapsed && "justify-center")}>
        <Server className="h-4 w-4 text-primary" />
        {!collapsed && (
          <span className="truncate text-sm text-sidebar-foreground/70">
            {lockedAsset ? lockedAsset.name : user.asset_id || "Locked"}
          </span>
        )}
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className={cn("flex items-center gap-3 rounded-lg px-3 py-2 text-sm", collapsed && "justify-center")}>
        <Server className="h-4 w-4 text-muted-foreground" />
        {!collapsed && <span className="text-muted-foreground">Loading...</span>}
      </div>
    );
  }

  if (assets.length === 0) {
    return (
      <div className={cn("flex items-center gap-3 rounded-lg px-3 py-2 text-sm", collapsed && "justify-center")}>
        <Server className="h-4 w-4 text-muted-foreground" />
        {!collapsed && <span className="text-muted-foreground text-xs">No servers</span>}
      </div>
    );
  }

  const selected = assets.find((a) => a.asset_id === selectedAssetId);

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          className={cn(
            "w-full justify-start gap-3 text-sidebar-foreground/70 hover:bg-sidebar-accent hover:text-sidebar-foreground",
            collapsed && "justify-center px-0"
          )}
        >
          <Server className={cn("h-4 w-4 shrink-0", selected && "text-primary")} />
          {!collapsed && (
            <span className="truncate text-sm">
              {selected ? selected.name : "All servers"}
            </span>
          )}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-56">
        <DropdownMenuItem onClick={() => setSelectedAssetId(null)}>
          <span className={cn("mr-2 h-2 w-2 rounded-full", !selectedAssetId ? "bg-primary" : "bg-transparent border border-muted-foreground")} />
          All servers
        </DropdownMenuItem>
        {assets.map((asset) => (
          <DropdownMenuItem key={asset.asset_id} onClick={() => setSelectedAssetId(asset.asset_id)}>
            <span className={cn("mr-2 h-2 w-2 rounded-full", selectedAssetId === asset.asset_id ? "bg-primary" : "bg-transparent border border-muted-foreground")} />
            <span className="truncate">{asset.name}</span>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function UserMenu({ collapsed }: { collapsed: boolean }) {
  const { user, logout } = useAuth();
  if (!user) return null;

  const initials = user.username
    .split(/[@.\s]+/)
    .map((p) => p[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();

  return (
    <div className={cn("flex items-center gap-3 rounded-lg px-3 py-2", collapsed && "justify-center")}>
      <div className="h-7 w-7 rounded-full bg-primary/10 flex items-center justify-center shrink-0">
        <span className="text-xs font-bold text-primary">{initials}</span>
      </div>
      {!collapsed && (
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium truncate">{user.username}</p>
          <p className="text-xs text-muted-foreground capitalize">{user.role.replace("_", " ")}</p>
        </div>
      )}
      {!collapsed && (
        <Button variant="ghost" size="icon" className="h-7 w-7 shrink-0" onClick={logout} title="Sign out">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/></svg>
        </Button>
      )}
    </div>
  );
}

function SidebarContent({ collapsed, setCollapsed }: { collapsed: boolean; setCollapsed?: (v: boolean) => void }) {
  const pathname = usePathname();
  const { theme, setTheme } = useTheme();
  const { isConnected } = useWebSocket();
  const [mounted, setMounted] = useState(false);

  // Track expanded sections — start empty (matches SSR), then hydrate from localStorage
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [navReady, setNavReady] = useState(false);

  useEffect(() => {
    setMounted(true);
    try {
      const saved = localStorage.getItem("aria:sidebar:expanded");
      if (saved) setExpanded(JSON.parse(saved));
    } catch {
      // ignore
    }
    setNavReady(true);
  }, []);

  const toggleSection = (label: string) => {
    setExpanded((prev) => {
      const isOpen = prev[label] !== false; // undefined or true = open
      const next = { ...prev, [label]: !isOpen };
      localStorage.setItem("aria:sidebar:expanded", JSON.stringify(next));
      return next;
    });
  };

  const isItemActive = (href: string) => pathname === href || (href !== "/" && pathname.startsWith(href));
  const isSectionExpanded = (section: NavSection) => {
    if (collapsed) return true; // always show when collapsed (icon-only)
    if (!navReady) return true; // SSR/default: show all to avoid mismatch
    // If explicitly set to false, check if any child is active (auto-expand active section)
    if (expanded[section.label] === false) {
      return section.items.some((item) => isItemActive(item.href));
    }
    return true; // default open
  };

  return (
    <>
      {/* Logo */}
      <div className="flex h-16 items-center justify-between border-b border-sidebar-border px-4">
        <Link href="/" className="flex items-center gap-3" onClick={() => setCollapsed?.(false)}>
          <div className="flex h-9 w-9 items-center justify-center rounded-lg overflow-hidden ring-1 ring-sidebar-border/50">
            <Image src="/aria-logo-icon.png" alt="ARIA" width={36} height={36} className="object-contain" priority />
          </div>
          {!collapsed && (
            <div className="flex flex-col">
              <span className="text-lg font-bold tracking-tight text-sidebar-foreground">
                {APP_BRAND}
              </span>
              <span className="text-xs text-sidebar-foreground/50">
                {APP_SUBTITLE}
              </span>
            </div>
          )}
        </Link>
        {setCollapsed && (
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8 text-sidebar-foreground hover:bg-sidebar-accent"
            onClick={() => setCollapsed(!collapsed)}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
          </Button>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-1 overflow-y-auto p-2">
        {navigationSections.map((section) => {
          const sectionOpen = isSectionExpanded(section);
          const hasActiveChild = section.items.some((item) => isItemActive(item.href));
          return (
            <div key={section.label} className="mb-2">
              {/* Section header with toggle */}
              {!collapsed && (
                <button
                  onClick={() => toggleSection(section.label)}
                  className={cn(
                    "mb-0.5 flex w-full items-center gap-2 rounded-md px-3 py-1.5 text-left transition-colors hover:bg-sidebar-accent/50",
                    hasActiveChild && "text-sidebar-primary"
                  )}
                >
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-sidebar-foreground/50">
                    {section.label}
                  </span>
                  <div className="flex-1" />
                  <ChevronDown
                    className={cn(
                      "h-3.5 w-3.5 shrink-0 text-sidebar-foreground/40 transition-transform duration-200",
                      sectionOpen && "rotate-180"
                    )}
                  />
                </button>
              )}
              {/* Section items */}
              <div
                className={cn(
                  "space-y-0.5 overflow-hidden transition-all duration-200",
                  !collapsed && !sectionOpen && "max-h-0 opacity-0",
                  !collapsed && sectionOpen && "max-h-96 opacity-100"
                )}
              >
                {section.items.map((item) => {
                  const isActive = isItemActive(item.href);
                  return (
                    <Link
                      key={item.name}
                      href={item.href}
                      onClick={() => setCollapsed?.(false)}
                      className={cn(
                        "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                        isActive
                          ? "bg-sidebar-accent text-sidebar-primary"
                          : "text-sidebar-foreground/70 hover:bg-sidebar-accent hover:text-sidebar-foreground"
                      )}
                    >
                      <item.icon className={cn("h-5 w-5 shrink-0", isActive && "text-sidebar-primary")} />
                      {!collapsed && <span>{item.name}</span>}
                    </Link>
                  );
                })}
              </div>
            </div>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="border-t border-sidebar-border p-2">
        {/* Connection Status */}
        <div
          className={cn(
            "flex items-center gap-3 rounded-lg px-3 py-2 text-sm",
            collapsed && "justify-center"
          )}
        >
          <div className="relative">
            <div
              className={cn(
                "h-2 w-2 rounded-full",
                isConnected ? "bg-success" : "bg-destructive"
              )}
            />
            {isConnected && (
              <div className="absolute inset-0 h-2 w-2 animate-pulse-ring rounded-full bg-success" />
            )}
          </div>
          {!collapsed && (
            <span className="text-muted-foreground">
              {isConnected ? "Connected" : "Disconnected"}
            </span>
          )}
        </div>

        {/* Asset Selector */}
        <AssetSelector collapsed={collapsed} />

        {/* User / Logout */}
        <UserMenu collapsed={collapsed} />

        {/* Theme Toggle */}
        {mounted && (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                className={cn(
                  "w-full justify-start gap-3 text-sidebar-foreground/70 hover:bg-sidebar-accent hover:text-sidebar-foreground",
                  collapsed && "justify-center px-0"
                )}
              >
                {theme === "dark" ? (
                  <Moon className="h-5 w-5" />
                ) : theme === "light" ? (
                  <Sun className="h-5 w-5" />
                ) : (
                  <Monitor className="h-5 w-5" />
                )}
                {!collapsed && <span className="capitalize">{theme} Theme</span>}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-40">
              <DropdownMenuItem onClick={() => setTheme("light")}>
                <Sun className="mr-2 h-4 w-4" />
                Light
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => setTheme("dark")}>
                <Moon className="mr-2 h-4 w-4" />
                Dark
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => setTheme("system")}>
                <Monitor className="mr-2 h-4 w-4" />
                System
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        )}

        {/* License */}
        {!collapsed && APP_LICENSEE && (
          <div className="mt-2 px-3 py-2">
            <p className="text-xs leading-tight text-sidebar-foreground/40">
              {APP_LICENSEE}
            </p>
          </div>
        )}
      </div>
    </>
  );
}

export function AppSidebar() {
  const isMobile = useIsMobile();
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  if (isMobile) {
    return (
      <>
        {/* Mobile Top Bar */}
        <header className="fixed top-0 left-0 right-0 z-50 flex h-14 items-center justify-between border-b border-border bg-background/95 px-4 backdrop-blur supports-[backdrop-filter]:bg-background/80">
          <div className="flex items-center gap-3">
            <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
              <SheetTrigger asChild>
                <Button variant="ghost" size="icon" aria-label="Open menu">
                  <Menu className="h-5 w-5" />
                </Button>
              </SheetTrigger>
              <SheetContent side="left" className="w-72 p-0 bg-sidebar border-r border-sidebar-border">
                <SheetTitle className="sr-only">Navigation Menu</SheetTitle>
                <div className="flex h-full flex-col">
                  <SidebarContent collapsed={false} setCollapsed={setMobileOpen} />
                </div>
              </SheetContent>
            </Sheet>
            <Link href="/" className="flex items-center gap-2">
              <div className="flex h-7 w-7 items-center justify-center rounded-md overflow-hidden ring-1 ring-border/50">
                <Image src="/aria-logo-icon.png" alt="ARIA" width={28} height={28} className="object-contain" priority />
              </div>
              <span className="text-base font-bold tracking-tight">{APP_BRAND}</span>
            </Link>
          </div>
        </header>
        {/* Spacer for fixed header */}
        <div className="h-14" />
      </>
    );
  }

  return (
    <aside
      className={cn(
        "flex h-screen flex-col border-r border-sidebar-border bg-sidebar transition-all duration-300",
        collapsed ? "w-16" : "w-64"
      )}
    >
      <SidebarContent collapsed={collapsed} setCollapsed={setCollapsed} />
    </aside>
  );
}
