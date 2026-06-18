"use client";

import { useState, useEffect, useMemo } from "react";
import { useAuth } from "@/lib/auth-context";
import { useRouter } from "next/navigation";
import { accountsAPI, assetsAPI, type MonitoredAsset } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Plus,
  Pencil,
  Lock,
  Ban,
  CheckCircle,
  Trash2,
  AlertTriangle,
  Search,
  Users,
  Server,
} from "lucide-react";

interface Account {
  id: string;
  username: string;
  email?: string | null;
  role: string;
  asset_id?: string | null;
  asset_name?: string | null;
  is_active: boolean;
  is_banned: boolean;
  created_at?: string | null;
  updated_at?: string | null;
  last_login_at?: string | null;
}

export default function AccountsPage() {
  const router = useRouter();
  const { user } = useAuth();
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editing, setEditing] = useState<Account | null>(null);
  const [resetPwOpen, setResetPwOpen] = useState(false);
  const [resetTarget, setResetTarget] = useState<Account | null>(null);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<Account | null>(null);
  const [newPw, setNewPw] = useState("");
  const [form, setForm] = useState({
    username: "",
    password: "",
    email: "",
    role: "server_user",
    asset_id: "",
    is_active: true,
  });
  const [error, setError] = useState("");
  const [assets, setAssets] = useState<MonitoredAsset[]>([]);

  useEffect(() => {
    if (user && user.role !== "super_admin") {
      router.push("/settings");
    }
  }, [user, router]);

  const load = async () => {
    setLoading(true);
    try {
      const data = await accountsAPI.list(search ? { search } : {});
      setAccounts(data.accounts || []);
    } catch (e: any) {
      setError(e.message || "Failed to load accounts");
    } finally {
      setLoading(false);
    }
  };

  const loadAssets = async () => {
    try {
      const data = await assetsAPI.list();
      setAssets(data.assets?.filter((a) => a.enabled) || []);
    } catch (e: any) {
      // silently fail — fallback to manual input
    }
  };

  useEffect(() => {
    if (user?.role === "super_admin") {
      load();
      loadAssets();
    }
  }, [user, search]);

  const isServerUser = form.role === "server_user";
  const selectedAsset = useMemo(() => assets.find((a) => a.asset_id === form.asset_id), [assets, form.asset_id]);

  const openAdd = () => {
    setEditing(null);
    setForm({ username: "", password: "", email: "", role: "server_user", asset_id: "", is_active: true });
    setError("");
    setDialogOpen(true);
  };

  const openEdit = (account: Account) => {
    setEditing(account);
    setForm({
      username: account.username,
      password: "",
      email: account.email || "",
      role: account.role,
      asset_id: account.asset_id || "",
      is_active: account.is_active,
    });
    setError("");
    setDialogOpen(true);
  };

  const save = async () => {
    setError("");
    if (isServerUser && !form.asset_id) {
      setError("Server user accounts must be assigned to a server.");
      return;
    }
    try {
      if (editing) {
        await accountsAPI.update(editing.id, {
          username: form.username,
          email: form.email || null,
          role: form.role,
          asset_id: isServerUser ? form.asset_id : null,
          is_active: form.is_active,
        });
      } else {
        await accountsAPI.create({
          username: form.username,
          password: form.password,
          email: form.email || null,
          role: form.role,
          asset_id: isServerUser ? form.asset_id : null,
          is_active: form.is_active,
        });
      }
      setDialogOpen(false);
      load();
    } catch (e: any) {
      setError(e.message || "Save failed");
    }
  };

  const doResetPw = async () => {
    if (!resetTarget || !newPw) return;
    try {
      await accountsAPI.resetPassword(resetTarget.id, newPw);
      setResetPwOpen(false);
      setNewPw("");
    } catch (e: any) {
      setError(e.message || "Reset failed");
    }
  };

  const doBan = async (account: Account) => {
    try {
      await accountsAPI.ban(account.id);
      load();
    } catch (e: any) {
      setError(e.message || "Ban failed");
    }
  };

  const doUnban = async (account: Account) => {
    try {
      await accountsAPI.unban(account.id);
      load();
    } catch (e: any) {
      setError(e.message || "Unban failed");
    }
  };

  const doDelete = async () => {
    if (!deleteTarget) return;
    try {
      await accountsAPI.delete(deleteTarget.id);
      setDeleteOpen(false);
      load();
    } catch (e: any) {
      setError(e.message || "Delete failed");
    }
  };

  if (!user || user.role !== "super_admin") {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        Access denied
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Accounts</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Manage ARIA login accounts and server-to-user mappings
          </p>
        </div>
        <Button onClick={openAdd}>
          <Plus className="mr-2 h-4 w-4" />
          Add Account
        </Button>
      </div>

      {error && (
        <div className="rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive flex items-center gap-2">
          <AlertTriangle className="h-4 w-4" />
          {error}
        </div>
      )}

      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center gap-3">
            <Users className="h-5 w-5 text-muted-foreground" />
            <CardTitle className="text-base font-medium">All Accounts</CardTitle>
          </div>
          <div className="mt-3 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search by username or email..."
              className="pl-9"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="text-sm text-muted-foreground">Loading...</div>
          ) : accounts.length === 0 ? (
            <div className="text-sm text-muted-foreground">No accounts found.</div>
          ) : (
            <div className="border rounded-lg overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Username</TableHead>
                    <TableHead>Role</TableHead>
                    <TableHead>Asset</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Last Login</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {accounts.map((a) => (
                    <TableRow key={a.id}>
                      <TableCell>
                        <div>
                          <p className="font-medium">{a.username}</p>
                          {a.email && <p className="text-xs text-muted-foreground">{a.email}</p>}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant={a.role === "super_admin" ? "default" : "secondary"} className="capitalize">
                          {a.role.replace("_", " ")}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <span className="text-sm text-muted-foreground">
                          {a.asset_name || a.asset_id || "—"}
                        </span>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          {a.is_banned ? (
                            <Badge variant="destructive">Banned</Badge>
                          ) : a.is_active ? (
                            <Badge variant="outline" className="text-success border-success/30">Active</Badge>
                          ) : (
                            <Badge variant="outline" className="text-muted-foreground">Inactive</Badge>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <span className="text-xs text-muted-foreground">
                          {a.last_login_at ? new Date(a.last_login_at).toLocaleString() : "Never"}
                        </span>
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1">
                          <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => openEdit(a)} title="Edit">
                            <Pencil className="h-3.5 w-3.5" />
                          </Button>
                          <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => { setResetTarget(a); setNewPw(""); setResetPwOpen(true); }} title="Reset password">
                            <Lock className="h-3.5 w-3.5" />
                          </Button>
                          {a.role !== "super_admin" && (
                            <>
                              {a.is_banned ? (
                                <Button variant="ghost" size="icon" className="h-7 w-7 text-success" onClick={() => doUnban(a)} title="Unban">
                                  <CheckCircle className="h-3.5 w-3.5" />
                                </Button>
                              ) : (
                                <Button variant="ghost" size="icon" className="h-7 w-7 text-warning" onClick={() => doBan(a)} title="Ban">
                                  <Ban className="h-3.5 w-3.5" />
                                </Button>
                              )}
                              <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive" onClick={() => { setDeleteTarget(a); setDeleteOpen(true); }} title="Delete">
                                <Trash2 className="h-3.5 w-3.5" />
                              </Button>
                            </>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Add / Edit Dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{editing ? "Edit Account" : "Add Account"}</DialogTitle>
            <DialogDescription>
              {editing ? "Update account details." : "Create a new ARIA login account."}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label>Username</Label>
              <Input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} placeholder="Username or email" />
            </div>
            {!editing && (
              <div className="space-y-2">
                <Label>Password</Label>
                <Input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} placeholder="Password" />
              </div>
            )}
            <div className="space-y-2">
              <Label>Email (optional)</Label>
              <Input value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} placeholder="email@example.com" />
            </div>
            <div className="space-y-2">
              <Label>Role</Label>
              <Select value={form.role} onValueChange={(v) => setForm({ ...form, role: v })}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="super_admin">Super Admin</SelectItem>
                  <SelectItem value="server_user">Server User</SelectItem>
                </SelectContent>
              </Select>
            </div>
            {isServerUser && (
              <div className="space-y-2">
                <Label>Assigned Server</Label>
                {assets.length > 0 ? (
                  <Select
                    value={form.asset_id || "__none__"}
                    onValueChange={(v) => setForm({ ...form, asset_id: v === "__none__" ? "" : v })}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select a server..." />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="__none__">
                        <span className="text-muted-foreground">— Select server —</span>
                      </SelectItem>
                      {assets.map((asset) => (
                        <SelectItem key={asset.asset_id} value={asset.asset_id}>
                          <div className="flex items-center gap-2">
                            <Server className="h-3.5 w-3.5 text-muted-foreground" />
                            <span>{asset.name}</span>
                            <span className="text-xs text-muted-foreground">({asset.asset_id})</span>
                          </div>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                ) : (
                  <Input
                    value={form.asset_id}
                    onChange={(e) => setForm({ ...form, asset_id: e.target.value })}
                    placeholder="e.g. web-server-01"
                  />
                )}
                {selectedAsset && (
                  <p className="text-xs text-muted-foreground">
                    {selectedAsset.ip_address && `IP: ${selectedAsset.ip_address} · `}
                    {selectedAsset.hostname && `Host: ${selectedAsset.hostname}`}
                  </p>
                )}
              </div>
            )}
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="is_active"
                checked={form.is_active}
                onChange={(e) => setForm({ ...form, is_active: e.target.checked })}
                className="h-4 w-4 rounded border-border"
              />
              <Label htmlFor="is_active" className="text-sm font-normal">Active</Label>
            </div>
            {error && <p className="text-sm text-destructive">{error}</p>}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)}>Cancel</Button>
            <Button onClick={save}>{editing ? "Save Changes" : "Create Account"}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Reset Password Dialog */}
      <Dialog open={resetPwOpen} onOpenChange={setResetPwOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Reset Password</DialogTitle>
            <DialogDescription>
              Set a new password for {resetTarget?.username}.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <Input type="password" value={newPw} onChange={(e) => setNewPw(e.target.value)} placeholder="New password" />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setResetPwOpen(false)}>Cancel</Button>
            <Button onClick={doResetPw}>Reset Password</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Dialog */}
      <Dialog open={deleteOpen} onOpenChange={setDeleteOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Delete Account</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete <strong>{deleteTarget?.username}</strong>? This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteOpen(false)}>Cancel</Button>
            <Button variant="destructive" onClick={doDelete}>Delete</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
