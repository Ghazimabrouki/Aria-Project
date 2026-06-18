"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  Shield,
  Database,
  Server,
  Brain,
  Terminal,
  Workflow,
  Activity,
  GitBranch,
  HardDrive,
  Users,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useAuth } from "@/lib/auth-context";

const baseSettingsNav = [
  { name: "Overview", href: "/settings", icon: LayoutDashboard },
  { name: "Assets", href: "/settings/assets", icon: HardDrive },
  { name: "Security", href: "/settings/security", icon: Shield },
  { name: "Data Sources", href: "/settings/data-sources", icon: Database },
  { name: "Redis", href: "/settings/redis", icon: Server },
  { name: "AI", href: "/settings/ai", icon: Brain },
  { name: "Ansible", href: "/settings/ansible", icon: Terminal },
  { name: "Workflow", href: "/settings/workflow", icon: Workflow },
  { name: "Monitoring", href: "/settings/monitoring", icon: Activity },
  { name: "Pipeline", href: "/settings/pipeline", icon: GitBranch },
];

export default function SettingsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const pathname = usePathname();
  const { user } = useAuth();

  const settingsNav = user?.role === "super_admin"
    ? [...baseSettingsNav, { name: "Accounts", href: "/settings/accounts", icon: Users }]
    : baseSettingsNav.filter(
        (item) => !["Assets", "Ansible", "Data Sources"].includes(item.name)
      );

  return (
    <div className="flex h-full">
      {/* Settings Sidebar */}
      <aside className="w-64 border-r border-border bg-card/50 overflow-y-auto">
        <div className="p-4">
          <h2 className="mb-4 px-3 text-sm font-semibold text-muted-foreground uppercase tracking-wider">
            Settings Center
          </h2>
          <nav className="space-y-1">
            {settingsNav.map((item) => {
              const isActive =
                pathname === item.href ||
                (item.href !== "/settings" && pathname.startsWith(item.href));
              return (
                <Link
                  key={item.name}
                  href={item.href}
                  className={cn(
                    "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                    isActive
                      ? "bg-primary/10 text-primary"
                      : "text-muted-foreground hover:bg-accent hover:text-foreground"
                  )}
                >
                  <item.icon className={cn("h-4 w-4 shrink-0", isActive && "text-primary")} />
                  {item.name}
                </Link>
              );
            })}
          </nav>
        </div>
      </aside>

      {/* Main Content */}
      <div className="flex-1 overflow-auto">{children}</div>
    </div>
  );
}
