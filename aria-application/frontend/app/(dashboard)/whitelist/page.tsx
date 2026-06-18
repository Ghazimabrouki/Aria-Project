"use client";
import { ListPageSkeleton } from "@/components/page-skeletons";

import { useState, Suspense } from "react";
import useSWR from "swr";
import { formatDistanceToNow } from "date-fns";
import {
  X,
  AlertTriangle,
  Plus,
  Trash2,
  ShieldCheck,
  Network,
  Globe,
  Tag,
  Search,
} from "lucide-react";
import {
  whitelistAPI,
  type WhitelistEntry,
  type WhitelistListResponse,
} from "@/lib/api";
import { PageHeader } from "@/components/page-header";
import { DataTable } from "@/components/data-table";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";

const typeOptions = [
  { value: "all", label: "All Types" },
  { value: "ip", label: "IP Address" },
  { value: "subnet", label: "Subnet" },
  { value: "domain", label: "Domain" },
];

const labelOptions = [
  { value: "all", label: "All Labels" },
  { value: "internal", label: "Internal" },
  { value: "trusted", label: "Trusted" },
  { value: "admin", label: "Admin" },
];

function TypeIcon({ type }: { type: string }) {
  if (type === "ip") return <ShieldCheck className="h-4 w-4 text-emerald-500" />;
  if (type === "subnet") return <Network className="h-4 w-4 text-blue-500" />;
  return <Globe className="h-4 w-4 text-violet-500" />;
}

function WhitelistPageInner() {
  const [offset, setOffset] = useState(0);
  const [typeFilter, setTypeFilter] = useState("all");
  const [labelFilter, setLabelFilter] = useState("all");
  const [searchValue, setSearchValue] = useState("");
  const [isAddOpen, setIsAddOpen] = useState(false);
  const [isCheckOpen, setIsCheckOpen] = useState(false);
  const [checkValue, setCheckValue] = useState("");
  const [checkResult, setCheckResult] = useState<boolean | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const [newEntry, setNewEntry] = useState({
    type: "ip",
    value: "",
    label: "trusted",
    description: "",
  });
  const [createError, setCreateError] = useState<string | null>(null);
  const [createLoading, setCreateLoading] = useState(false);

  const limit = 20;

  const { data, error, isLoading, mutate } = useSWR<WhitelistListResponse>(
    ["whitelist", offset, typeFilter, labelFilter],
    () =>
      whitelistAPI.list({
        type: typeFilter !== "all" ? typeFilter : undefined,
        label: labelFilter !== "all" ? labelFilter : undefined,
      })
  );

  const entries = data?.entries || [];
  const filteredEntries = searchValue
    ? entries.filter(
        (e) =>
          e.value.toLowerCase().includes(searchValue.toLowerCase()) ||
          (e.description && e.description.toLowerCase().includes(searchValue.toLowerCase()))
      )
    : entries;

  const total = searchValue ? filteredEntries.length : data?.total || 0;
  const totalPages = Math.ceil(total / limit);
  const currentPage = Math.floor(offset / limit) + 1;

  const paginatedEntries = searchValue
    ? filteredEntries.slice(offset, offset + limit)
    : filteredEntries;

  const handlePageChange = (page: number) => {
    setOffset((page - 1) * limit);
  };

  const handleCreate = async () => {
    if (!newEntry.value.trim()) return;
    setCreateError(null);
    setCreateLoading(true);
    try {
      await whitelistAPI.create({
        type: newEntry.type,
        value: newEntry.value.trim(),
        label: newEntry.label,
        description: newEntry.description.trim() || undefined,
      });
      setIsAddOpen(false);
      setNewEntry({ type: "ip", value: "", label: "trusted", description: "" });
      mutate();
    } catch (err: any) {
      setCreateError(err?.message || "Failed to create entry. It may already exist.");
    } finally {
      setCreateLoading(false);
    }
  };

  const handleDelete = async (id: string) => {
    setDeletingId(id);
    try {
      await whitelistAPI.delete(id);
      mutate();
    } catch (err) {
      console.error("Failed to delete whitelist entry:", err);
    } finally {
      setDeletingId(null);
    }
  };

  const handleCheck = async () => {
    if (!checkValue.trim()) return;
    try {
      const res = await whitelistAPI.check(checkValue.trim());
      setCheckResult(res.whitelisted);
    } catch (err) {
      console.error("Failed to check whitelist:", err);
    }
  };

  const clearFilters = () => {
    setTypeFilter("all");
    setLabelFilter("all");
    setSearchValue("");
    setOffset(0);
  };

  const hasFilters = typeFilter !== "all" || labelFilter !== "all" || searchValue !== "";

  const stats = {
    total: data?.total || 0,
    by_type: {
      ip: data?.entries.filter((e) => e.type === "ip").length || 0,
      subnet: data?.entries.filter((e) => e.type === "subnet").length || 0,
      domain: data?.entries.filter((e) => e.type === "domain").length || 0,
    },
  };

  const columns = [
    {
      key: "type",
      header: "Type",
      cell: (entry: WhitelistEntry) => (
        <div className="flex items-center gap-2">
          <TypeIcon type={entry.type} />
          <Badge variant="outline" className="capitalize text-xs">
            {entry.type}
          </Badge>
        </div>
      ),
      className: "w-32",
    },
    {
      key: "value",
      header: "Value",
      cell: (entry: WhitelistEntry) => (
        <div className="max-w-xs">
          <code className="bg-muted px-2 py-1 rounded text-sm font-mono">{entry.value}</code>
        </div>
      ),
    },
    {
      key: "label",
      header: "Label",
      cell: (entry: WhitelistEntry) => (
        <Badge variant="secondary" className="capitalize text-xs">
          <Tag className="mr-1 h-2.5 w-2.5" />
          {entry.label}
        </Badge>
      ),
      className: "w-28",
    },
    {
      key: "description",
      header: "Description",
      cell: (entry: WhitelistEntry) => (
        <span className="text-sm text-muted-foreground truncate max-w-[200px] block">
          {entry.description || "—"}
        </span>
      ),
    },
    {
      key: "created",
      header: "Created",
      cell: (entry: WhitelistEntry) => {
        // API may return naive ISO strings (SQLite stores UTC without tzinfo).
        // Treat missing timezone as UTC so local browser offset doesn't skew the display.
        const raw = entry.created_at;
        const iso = raw && !raw.endsWith("Z") && !/[+-]\d{2}:\d{2}$/.test(raw) ? raw + "Z" : raw;
        const date = iso ? new Date(iso) : null;
        return (
          <span className="text-sm text-muted-foreground">
            {date && !isNaN(date.getTime())
              ? formatDistanceToNow(date, { addSuffix: true })
              : "—"}
          </span>
        );
      },
      className: "w-36",
    },
    {
      key: "actions",
      header: "",
      cell: (entry: WhitelistEntry) => (
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8 text-muted-foreground hover:text-destructive"
          title="Delete entry"
          disabled={deletingId === entry.id}
          onClick={(e) => {
            e.stopPropagation();
            handleDelete(entry.id);
          }}
        >
          <Trash2 className="h-4 w-4" />
        </Button>
      ),
      className: "w-16",
    },
  ];

  return (
    <div className="flex flex-col">
      <PageHeader
        title="Whitelist"
        description="Manage approved IPs, subnets, and domains that are excluded from blocking actions"
        onRefresh={() => mutate()}
        isLoading={isLoading}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => setIsCheckOpen(true)}>
              <Search className="mr-1 h-4 w-4" />
              Check
            </Button>
            <Button size="sm" onClick={() => setIsAddOpen(true)}>
              <Plus className="mr-1 h-4 w-4" />
              Add Entry
            </Button>
          </div>
        }
      />

      <div className="flex-1 p-6 space-y-4">
        <Card className="border-muted bg-muted/30">
          <CardContent className="flex items-center gap-3 py-3">
            <Globe className="h-5 w-5 text-muted-foreground" />
            <span className="text-sm text-muted-foreground">
              Global whitelist — applies to all servers
            </span>
          </CardContent>
        </Card>

        {/* Stats Cards */}
        {data && (
          <div className="grid gap-4 md:grid-cols-4">
            <Card>
              <CardContent className="pt-6">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Total Entries</p>
                  <p className="text-2xl font-bold">{stats.total.toLocaleString()}</p>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">IP Addresses</p>
                  <p className="text-2xl font-bold">{stats.by_type.ip.toLocaleString()}</p>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Subnets</p>
                  <p className="text-2xl font-bold">{stats.by_type.subnet.toLocaleString()}</p>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Domains</p>
                  <p className="text-2xl font-bold">{stats.by_type.domain.toLocaleString()}</p>
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Filters */}
        <div className="flex items-center gap-2">
          <Select
            value={typeFilter}
            onValueChange={(v) => {
              setTypeFilter(v);
              setOffset(0);
            }}
          >
            <SelectTrigger className="w-36 max-sm:w-full">
              <SelectValue placeholder="Type" />
            </SelectTrigger>
            <SelectContent>
              {typeOptions.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>
                  {opt.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select
            value={labelFilter}
            onValueChange={(v) => {
              setLabelFilter(v);
              setOffset(0);
            }}
          >
            <SelectTrigger className="w-36 max-sm:w-full">
              <SelectValue placeholder="Label" />
            </SelectTrigger>
            <SelectContent>
              {labelOptions.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>
                  {opt.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search value or description..."
              className="w-64 pl-9"
              value={searchValue}
              onChange={(e) => {
                setSearchValue(e.target.value);
                setOffset(0);
              }}
            />
          </div>
          {hasFilters && (
            <Button variant="ghost" size="sm" onClick={clearFilters}>
              <X className="mr-1 h-4 w-4" />
              Clear
            </Button>
          )}
        </div>

        {error ? (
          <div className="flex h-64 flex-col items-center justify-center rounded-lg border border-destructive/50 bg-destructive/5 p-6 text-center">
            <AlertTriangle className="h-10 w-10 text-destructive" />
            <p className="mt-4 text-lg font-medium">Failed to load whitelist</p>
            <p className="text-sm text-muted-foreground">
              {error.message || "Something went wrong. Please try again."}
            </p>
            <Button variant="outline" className="mt-4" onClick={() => mutate()}>
              Retry
            </Button>
          </div>
        ) : (
          <DataTable
            columns={columns}
            data={paginatedEntries}
            page={currentPage}
            totalPages={totalPages}
            onPageChange={handlePageChange}
            isLoading={isLoading}
            emptyMessage="No whitelist entries found"
          />
        )}
      </div>

      {/* Add Entry Dialog */}
      <Dialog open={isAddOpen} onOpenChange={setIsAddOpen}>
        <DialogContent className="sm:max-w-[480px]">
          <DialogHeader>
            <DialogTitle>Add Whitelist Entry</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label htmlFor="type">Type</Label>
              <Select
                value={newEntry.type}
                onValueChange={(v) => setNewEntry({ ...newEntry, type: v })}
              >
                <SelectTrigger id="type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ip">IP Address</SelectItem>
                  <SelectItem value="subnet">Subnet (CIDR)</SelectItem>
                  <SelectItem value="domain">Domain</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="value">
                Value
                {newEntry.type === "ip" && (
                  <span className="text-muted-foreground font-normal ml-1">(e.g. 192.168.1.1)</span>
                )}
                {newEntry.type === "subnet" && (
                  <span className="text-muted-foreground font-normal ml-1">(e.g. 10.0.0.0/8)</span>
                )}
                {newEntry.type === "domain" && (
                  <span className="text-muted-foreground font-normal ml-1">(e.g. example.com)</span>
                )}
              </Label>
              <Input
                id="value"
                placeholder={`Enter ${newEntry.type}...`}
                value={newEntry.value}
                onChange={(e) => setNewEntry({ ...newEntry, value: e.target.value })}
                onKeyDown={(e) => e.key === "Enter" && handleCreate()}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="label">Label</Label>
              <Select
                value={newEntry.label}
                onValueChange={(v) => setNewEntry({ ...newEntry, label: v })}
              >
                <SelectTrigger id="label">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="internal">Internal</SelectItem>
                  <SelectItem value="trusted">Trusted</SelectItem>
                  <SelectItem value="admin">Admin</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="description">Description (optional)</Label>
              <Textarea
                id="description"
                placeholder="Why is this entry whitelisted?"
                value={newEntry.description}
                onChange={(e) => setNewEntry({ ...newEntry, description: e.target.value })}
                rows={3}
              />
            </div>
            {createError && (
              <div className="rounded-md border border-destructive/50 bg-destructive/5 p-3 text-sm text-destructive">
                {createError}
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsAddOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleCreate}
              disabled={createLoading || !newEntry.value.trim()}
            >
              {createLoading ? "Adding..." : "Add Entry"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Check Dialog */}
      <Dialog open={isCheckOpen} onOpenChange={setIsCheckOpen}>
        <DialogContent className="sm:max-w-[480px]">
          <DialogHeader>
            <DialogTitle>Check Whitelist</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label htmlFor="check-value">Value to check</Label>
              <Input
                id="check-value"
                placeholder="IP, subnet, or domain..."
                value={checkValue}
                onChange={(e) => {
                  setCheckValue(e.target.value);
                  setCheckResult(null);
                }}
                onKeyDown={(e) => e.key === "Enter" && handleCheck()}
              />
            </div>
            {checkResult !== null && (
              <div
                className={cn(
                  "rounded-md border p-3 text-sm flex items-center gap-2",
                  checkResult
                    ? "border-emerald-500/50 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                    : "border-muted bg-muted/50 text-muted-foreground"
                )}
              >
                {checkResult ? (
                  <>
                    <ShieldCheck className="h-4 w-4" />
                    This value is whitelisted.
                  </>
                ) : (
                  <>
                    <X className="h-4 w-4" />
                    This value is not whitelisted.
                  </>
                )}
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsCheckOpen(false)}>
              Close
            </Button>
            <Button onClick={handleCheck} disabled={!checkValue.trim()}>
              Check
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

export default function WhitelistPage() {
  return (
    <Suspense fallback={<ListPageSkeleton filterCount={2} />}>
      <WhitelistPageInner />
    </Suspense>
  );
}
