/**
 * In-memory admin secret session helper.
 *
 * - Stores secret only in module-level variable (memory).
 * - Clears on page refresh.
 * - Never uses localStorage, cookies, or other persistent storage.
 */

let _adminSecret: string | null = null;

export function getAdminSecret(): string | null {
  return _adminSecret;
}

export function setAdminSecret(secret: string): void {
  _adminSecret = secret;
}

export function clearAdminSecret(): void {
  _adminSecret = null;
}

export function hasAdminSecret(): boolean {
  return _adminSecret !== null && _adminSecret.length > 0;
}

export class AdminSecretRequiredError extends Error {
  constructor() {
    super("Admin action requires X-ARIA-Admin-Secret header.");
    this.name = "AdminSecretRequiredError";
  }
}

/**
 * Require an admin secret to perform an action.
 *
 * If a secret is already in memory, calls callback immediately.
 * If not, returns false so the caller can open the unlock modal.
 */
export function requireAdminSecret(
  callback: (secret: string) => void
): boolean {
  const secret = getAdminSecret();
  if (secret) {
    callback(secret);
    return true;
  }
  return false;
}

// ── Global promise-based secret request (used by fetchAPI interceptor) ──

let _pendingResolvers: Array<{ resolve: (secret: string) => void; reject: (reason?: any) => void }> = [];

/**
 * Request the admin secret from the user via the global dialog.
 * Returns a Promise that resolves when the user enters the secret.
 * Rejects if the user cancels.
 */
export function requestAdminSecret(errorMessage?: string): Promise<string> {
  // If we already have one, return immediately
  const existing = getAdminSecret();
  if (existing) return Promise.resolve(existing);

  // Emit global event so the dialog opens
  if (typeof window !== "undefined") {
    window.dispatchEvent(
      new CustomEvent("aria:admin-secret-required", {
        detail: { errorMessage },
      })
    );
  }

  return new Promise((resolve, reject) => {
    _pendingResolvers.push({ resolve, reject });
  });
}

/**
 * Called by the global dialog when the user submits a secret.
 */
export function resolveAdminSecretRequest(secret: string): void {
  const pending = _pendingResolvers;
  _pendingResolvers = [];
  pending.forEach(({ resolve }) => resolve(secret));
}

/**
 * Called by the global dialog when the user cancels.
 */
export function rejectAdminSecretRequest(reason?: string): void {
  const pending = _pendingResolvers;
  _pendingResolvers = [];
  const err = new Error(reason || "Admin secret required.");
  pending.forEach(({ reject }) => reject(err));
}
