"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
  CommandShortcut,
} from "@/components/ui/command";
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
  Globe,
  Terminal,
  HardDrive,
  Settings,
  Server,
  Moon,
  Sun,
  Monitor,
  ArrowRight,
} from "lucide-react";
import { useTheme } from "@/components/theme-provider";

const navigation = [
  { name: "Dashboard", href: "/", icon: LayoutDashboard, shortcut: "G D" },
  { name: "Search", href: "/search", icon: Search, shortcut: "G S" },
  { name: "Alerts", href: "/alerts", icon: AlertTriangle, shortcut: "G A" },
  { name: "Incidents", href: "/incidents", icon: FileWarning, shortcut: "G I" },
  { name: "Investigations", href: "/investigations", icon: Shield, shortcut: "G N" },
  { name: "Runtime Security", href: "/runtime/investigations", icon: ShieldCheck },
  { name: "Infrastructure", href: "/infrastructure/investigations", icon: HardDrive },
  { name: "AI Assistant", href: "/assistant", icon: Bot },
  { name: "AI Operator", href: "/operator", icon: Terminal },
  { name: "IPS Map", href: "/ips", icon: Globe },
  { name: "Whitelist", href: "/whitelist", icon: ShieldCheck },
  { name: "Performance", href: "/metrics", icon: Activity },
  { name: "Archives", href: "/archives", icon: Archive },
  { name: "Settings", href: "/settings", icon: Settings, shortcut: "G T" },
];

export function GlobalCommandMenu() {
  const [open, setOpen] = React.useState(false);
  const router = useRouter();
  const { theme, setTheme } = useTheme();

  React.useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if (e.key === "k" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen((open) => !open);
      }

      // Quick nav shortcuts when not typing in an input
      if (
        e.target instanceof HTMLInputElement ||
        e.target instanceof HTMLTextAreaElement ||
        e.target instanceof HTMLSelectElement
      ) {
        return;
      }

      if (e.key === "g" || e.key === "G") {
        // Wait for next key
        const handler = (ev: KeyboardEvent) => {
          if (ev.key === "d" || ev.key === "D") router.push("/");
          if (ev.key === "a" || ev.key === "A") router.push("/alerts");
          if (ev.key === "i" || ev.key === "I") router.push("/incidents");
          if (ev.key === "n" || ev.key === "N") router.push("/investigations");
          if (ev.key === "s" || ev.key === "S") router.push("/search");
          if (ev.key === "t" || ev.key === "T") router.push("/settings");
          window.removeEventListener("keydown", handler);
        };
        window.addEventListener("keydown", handler, { once: true });
      }
    };

    document.addEventListener("keydown", down);
    return () => document.removeEventListener("keydown", down);
  }, [router]);

  const runCommand = React.useCallback(
    (command: () => void) => {
      setOpen(false);
      command();
    },
    []
  );

  return (
    <CommandDialog open={open} onOpenChange={setOpen}>
      <CommandInput placeholder="Type a command or search pages..." />
      <CommandList>
        <CommandEmpty>No results found.</CommandEmpty>
        <CommandGroup heading="Navigation">
          {navigation.map((item) => (
            <CommandItem
              key={item.name}
              onSelect={() => runCommand(() => router.push(item.href))}
            >
              <item.icon className="mr-2 h-4 w-4" />
              <span>{item.name}</span>
              {item.shortcut && (
                <CommandShortcut>{item.shortcut}</CommandShortcut>
              )}
              <ArrowRight className="ml-auto h-3.5 w-3.5 text-muted-foreground opacity-0 group-hover:opacity-100" />
            </CommandItem>
          ))}
        </CommandGroup>
        <CommandSeparator />
        <CommandGroup heading="Preferences">
          <CommandItem
            onSelect={() => runCommand(() => setTheme("light"))}
            disabled={theme === "light"}
          >
            <Sun className="mr-2 h-4 w-4" />
            <span>Light Theme</span>
          </CommandItem>
          <CommandItem
            onSelect={() => runCommand(() => setTheme("dark"))}
            disabled={theme === "dark"}
          >
            <Moon className="mr-2 h-4 w-4" />
            <span>Dark Theme</span>
          </CommandItem>
          <CommandItem
            onSelect={() => runCommand(() => setTheme("system"))}
            disabled={theme === "system"}
          >
            <Monitor className="mr-2 h-4 w-4" />
            <span>System Theme</span>
          </CommandItem>
        </CommandGroup>
      </CommandList>
    </CommandDialog>
  );
}
