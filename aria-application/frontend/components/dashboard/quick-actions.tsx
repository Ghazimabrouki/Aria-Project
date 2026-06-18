"use client";

import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Search,
  AlertTriangle,
  FileWarning,
  Clock,
  ArrowRight,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";

interface QuickActionsProps {
  pendingApprovals: number;
  activeInvestigations: number;
}

export function QuickActions({ pendingApprovals, activeInvestigations }: QuickActionsProps) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-base font-medium">Quick Actions</CardTitle>
      </CardHeader>
      <CardContent className="pt-0">
        <div className="space-y-2">
          {pendingApprovals > 0 && (
            <Link href="/investigations?status=awaiting_approval">
              <div className="flex items-center justify-between rounded-lg border border-warning/40 bg-warning/5 p-2.5 transition-colors hover:bg-warning/10">
                <div className="flex items-center gap-2.5">
                  <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-warning/10">
                    <Clock className="h-4 w-4 text-warning" />
                  </div>
                  <div>
                    <p className="text-sm font-medium">Pending Approvals</p>
                    <p className="text-xs text-muted-foreground">
                      Review playbooks awaiting approval
                    </p>
                  </div>
                </div>
                <Badge variant="outline" className="border-warning text-warning text-xs">
                  {pendingApprovals}
                </Badge>
              </div>
            </Link>
          )}

          {activeInvestigations > 0 && (
            <Link href="/investigations?status=running">
              <div className="flex items-center justify-between rounded-lg border border-primary/40 bg-primary/5 p-2.5 transition-colors hover:bg-primary/10">
                <div className="flex items-center gap-2.5">
                  <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/10">
                    <Search className="h-4 w-4 text-primary" />
                  </div>
                  <div>
                    <p className="text-sm font-medium">Active Investigations</p>
                    <p className="text-xs text-muted-foreground">
                      Monitor ongoing investigations
                    </p>
                  </div>
                </div>
                <Badge variant="outline" className="border-primary text-primary text-xs">
                  {activeInvestigations}
                </Badge>
              </div>
            </Link>
          )}

          <div className="grid grid-cols-2 gap-2 pt-1">
            <Button variant="outline" className="h-auto flex-col gap-1 py-3" asChild>
              <Link href="/alerts">
                <AlertTriangle className="h-4 w-4 text-muted-foreground" />
                <span className="text-xs">View Alerts</span>
              </Link>
            </Button>
            <Button variant="outline" className="h-auto flex-col gap-1 py-3" asChild>
              <Link href="/incidents">
                <FileWarning className="h-4 w-4 text-muted-foreground" />
                <span className="text-xs">View Incidents</span>
              </Link>
            </Button>
          </div>

          <Button className="w-full" size="sm" asChild>
            <Link href="/assistant">
              Ask AI Assistant
              <ArrowRight className="ml-2 h-3.5 w-3.5" />
            </Link>
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
