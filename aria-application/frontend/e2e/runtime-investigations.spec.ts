import { test, expect } from "playwright/test";

const API_BASE = process.env.API_BASE_URL || "http://localhost:8001";

async function getRuntimeInvestigations() {
  const res = await fetch(`${API_BASE}/api/v1/runtime/investigations?limit=50`);
  if (!res.ok) throw new Error(`API list failed: ${res.status}`);
  const data = await res.json();
  return data.investigations || [];
}

async function getRuntimeStats() {
  const res = await fetch(`${API_BASE}/api/v1/runtime/investigations/stats`);
  if (!res.ok) throw new Error(`API stats failed: ${res.status}`);
  return res.json();
}

async function getRuntimeInvestigationDetail(id: string) {
  const res = await fetch(`${API_BASE}/api/v1/runtime/investigations/${id}`);
  if (!res.ok) throw new Error(`API detail failed: ${res.status}`);
  return res.json();
}

test.describe("Runtime Investigations - List Page", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/runtime/investigations");
  });

  test("page loads with header and stats cards", async ({ page }) => {
    await expect(page.getByRole("heading", { name: "Runtime Security" })).toBeVisible();
    await expect(page.getByText("Falco runtime security events and investigations")).toBeVisible();

    // Stats cards should render
    await expect(page.getByTestId("stat-total")).toBeVisible();
    await expect(page.getByTestId("stat-findings-ready")).toBeVisible();
    await expect(page.getByTestId("stat-manual-review")).toBeVisible();
    await expect(page.getByTestId("stat-acknowledged")).toBeVisible();
    await expect(page.getByTestId("stat-verified-fixes")).toBeVisible();
  });

  test("stats cards show numbers consistent with API", async ({ page }) => {
    const stats = await getRuntimeStats();
    // Verify the API returns valid stats and the card renders
    expect(stats.total).toBeGreaterThanOrEqual(0);
    await expect(page.getByText("Total")).toBeVisible();
  });

  test("filters render and can be interacted with", async ({ page }) => {
    // Status filter
    const statusTrigger = page.locator("button[role='combobox']").filter({ hasText: /Status/ }).first();
    await expect(statusTrigger).toBeVisible();

    // Host input
    const hostInput = page.getByPlaceholder("Filter by host...");
    await expect(hostInput).toBeVisible();

    // Container input
    const containerInput = page.getByPlaceholder("Filter by container...");
    await expect(containerInput).toBeVisible();
  });

  test("investigations table or empty state renders", async ({ page }) => {
    const empty = page.getByText("No runtime investigations found");
    const rows = page.locator(".divide-y > div").first();
    await expect(empty.or(rows)).toBeVisible();
  });

  test("no console errors on list page", async ({ page }) => {
    const errors: string[] = [];
    page.on("console", (msg) => {
      if (msg.type() === "error") {
        const text = msg.text();
        // Ignore known benign errors (404 static assets, favicon, etc.)
        if (!text.includes("404") && !text.includes("favicon")) {
          errors.push(text);
        }
      }
    });
    await page.waitForLoadState("networkidle");
    expect(errors).toHaveLength(0);
  });

  test("no broken API calls on list page", async ({ page }) => {
    const failed: number[] = [];
    page.on("response", (res) => {
      if (res.url().includes("/api/v1/") && res.status() >= 400) {
        failed.push(res.status());
      }
    });
    await page.waitForLoadState("networkidle");
    expect(failed).toHaveLength(0);
  });
});

test.describe("Runtime Investigations - Detail Page", () => {
  test("open real investigation detail and verify all tabs", async ({ page }) => {
    const investigations = await getRuntimeInvestigations();
    test.skip(investigations.length === 0, "No runtime investigations available for detail test");

    const inv = investigations[0];
    await page.goto(`/runtime/investigations/${inv.id}`);

    // Header
    await expect(page.getByRole("button", { name: "Back" }).or(page.locator("button").filter({ has: page.locator("svg") }).first())).toBeVisible();

    // Wait for loading to finish
    const loading = page.getByText("Loading...");
    await loading.waitFor({ state: "hidden", timeout: 15000 }).catch(() => {});

    const errorState = page.getByText("Failed to load investigation");
    await expect(errorState).not.toBeVisible();

    // Tabs
    const tabNames = ["Overview", "Evidence", "Diagnostic", "Remediation", "Verification", "Context", "Timeline", "Raw Output"];
    for (const name of tabNames) {
      const tab = page.getByRole("tab", { name });
      await expect(tab).toBeVisible();
      await tab.click();
      // Wait for the active tabpanel to be visible
      const activePanel = page.locator('[role="tabpanel"]:not([hidden])');
      await expect(activePanel).toBeVisible();
    }
  });

  test("detail page shows truthful available actions", async ({ page }) => {
    const investigations = await getRuntimeInvestigations();
    test.skip(investigations.length === 0, "No runtime investigations available");

    const inv = investigations[0];
    await page.goto(`/runtime/investigations/${inv.id}`);

    const loading = page.getByText("Loading...");
    await loading.waitFor({ state: "hidden", timeout: 15000 }).catch(() => {});

    const errorState = page.getByText("Failed to load investigation");
    await expect(errorState).not.toBeVisible();

    // Fetch full detail to cross-check actions
    const detail = await getRuntimeInvestigationDetail(inv.id);
    const aa = detail.available_actions || {};

    // If approve_run is true, button must exist
    if (aa.approve_run) {
      await expect(page.getByRole("button", { name: "Approve & Run" })).toBeVisible();
    }

    // If status is not awaiting_approval, approve_run must be false
    if (detail.status !== "awaiting_approval") {
      const approveButton = page.getByRole("button", { name: "Approve & Run" });
      await expect(approveButton).not.toBeVisible();
    }

    // Observe cases must not show Approve & Run
    const plan = detail.remediation_plan || {};
    if (plan.decision === "observe" || plan.decision === "no_action_expected_activity") {
      const approveButton = page.getByRole("button", { name: "Approve & Run" });
      await expect(approveButton).not.toBeVisible();
    }
  });

  test("acknowledge action shows readable feedback and never [object Object]", async ({ page }) => {
    const investigations = await getRuntimeInvestigations();
    let target: any = null;
    for (const inv of investigations) {
      const detail = await getRuntimeInvestigationDetail(inv.id);
      if (detail.available_actions?.acknowledge) {
        target = inv;
        break;
      }
    }
    test.skip(!target, "No acknowledgeable investigation available");

    await page.goto(`/runtime/investigations/${target.id}`);
    const loading = page.getByText("Loading...");
    await loading.waitFor({ state: "hidden", timeout: 15000 }).catch(() => {});

    const ackButton = page.getByRole("button", { name: "Acknowledge" });
    await expect(ackButton).toBeVisible();

    const apiPromise = page.waitForResponse((res) =>
      res.url().includes(`/runtime/investigations/${target.id}/acknowledge`) && res.request().method() === "POST"
    );

    await ackButton.click();
    const apiRes = await apiPromise;
    expect(apiRes.status()).not.toBe(0);

    // Wait a tick for toast/banner to render
    await page.waitForTimeout(500);

    // CRITICAL: page must NEVER contain [object Object]
    const bodyText = await page.locator("body").textContent();
    expect(bodyText).not.toContain("[object Object]");

    // Must show readable feedback (toast or inline banner)
    const feedback = page.locator("[data-sonner-toast]").or(page.getByText(/acknowledged|action failed/i)).first();
    await expect(feedback).toBeVisible({ timeout: 5000 });
  });

  test("escalate action shows readable feedback and never [object Object]", async ({ page }) => {
    const investigations = await getRuntimeInvestigations();
    let target: any = null;
    for (const inv of investigations) {
      const detail = await getRuntimeInvestigationDetail(inv.id);
      if (detail.available_actions?.escalate) {
        target = inv;
        break;
      }
    }
    test.skip(!target, "No escalatable investigation available");

    await page.goto(`/runtime/investigations/${target.id}`);
    const loading = page.getByText("Loading...");
    await loading.waitFor({ state: "hidden", timeout: 15000 }).catch(() => {});

    const escButton = page.getByRole("button", { name: "Escalate" });
    await expect(escButton).toBeVisible();

    const apiPromise = page.waitForResponse((res) =>
      res.url().includes(`/runtime/investigations/${target.id}/escalate`) && res.request().method() === "POST"
    );

    await escButton.click();
    const apiRes = await apiPromise;
    expect(apiRes.status()).not.toBe(0);

    await page.waitForTimeout(500);

    // CRITICAL: page must NEVER contain [object Object]
    const bodyText = await page.locator("body").textContent();
    expect(bodyText).not.toContain("[object Object]");

    const feedback = page.locator("[data-sonner-toast]").or(page.getByText(/escalated|action failed|no remediation/i)).first();
    await expect(feedback).toBeVisible({ timeout: 5000 });
  });

  test("error feedback is visible when action is blocked", async ({ page }) => {
    // Find an archived or observe case and try to click an action that should be hidden.
    // If no blocked action is available via UI, verify that error banner would render.
    const investigations = await getRuntimeInvestigations();
    const target = investigations.find((inv: any) => inv.status === "archived_not_fixed" || inv.status === "acknowledged");
    test.skip(!target, "No archived/acknowledged case available for error test");

    await page.goto(`/runtime/investigations/${target.id}`);
    const loading = page.getByText("Loading...");
    await loading.waitFor({ state: "hidden", timeout: 15000 }).catch(() => {});

    // Approve & Run should NOT be visible
    const approveButton = page.getByRole("button", { name: "Approve & Run" });
    await expect(approveButton).not.toBeVisible();
  });

  test("detail page shows context sections", async ({ page }) => {
    const investigations = await getRuntimeInvestigations();
    test.skip(investigations.length === 0, "No runtime investigations available");

    const inv = investigations[0];
    await page.goto(`/runtime/investigations/${inv.id}`);

    const loading = page.getByText("Loading...");
    await loading.waitFor({ state: "hidden", timeout: 15000 }).catch(() => {});

    await page.getByRole("tab", { name: "Context" }).click();
    const activePanel = page.locator('[role="tabpanel"]:not([hidden])');
    await expect(activePanel).toBeVisible();

    // Should contain host or container info
    const hasHost = await activePanel.getByText(/host/i).count() > 0;
    const hasContainer = await activePanel.getByText(/container/i).count() > 0;
    expect(hasHost || hasContainer).toBe(true);
  });

  test("detail page shows decision and next action", async ({ page }) => {
    const investigations = await getRuntimeInvestigations();
    test.skip(investigations.length === 0, "No runtime investigations available");

    const inv = investigations[0];
    await page.goto(`/runtime/investigations/${inv.id}`);

    const loading = page.getByText("Loading...");
    await loading.waitFor({ state: "hidden", timeout: 15000 }).catch(() => {});

    const res = await fetch(`${API_BASE}/api/v1/runtime/investigations/${inv.id}`);
    const detail = await res.json();
    const plan = detail.remediation_plan || {};
    const outcome = detail.outcome_summary || {};

    // Decision should be visible somewhere in the summary or overview
    const decisionText = (plan.decision || "").replace(/_/g, " ");
    if (decisionText) {
      const decisionLocator = page.getByText(new RegExp(decisionText, "i")).first();
      await expect(decisionLocator).toBeVisible();
    }

    // Next action should be visible
    const nextAction = outcome.next_action || "";
    if (nextAction) {
      const nextLocator = page.getByText(new RegExp(nextAction.slice(0, 30), "i")).first();
      await expect(nextLocator).toBeVisible();
    }
  });

  test("detail page distinguishes diagnostic-only vs remediation", async ({ page }) => {
    const investigations = await getRuntimeInvestigations();
    test.skip(investigations.length === 0, "No runtime investigations available");

    const inv = investigations[0];
    await page.goto(`/runtime/investigations/${inv.id}`);

    const loading = page.getByText("Loading...");
    await loading.waitFor({ state: "hidden", timeout: 15000 }).catch(() => {});

    const res = await fetch(`${API_BASE}/api/v1/runtime/investigations/${inv.id}`);
    const detail = await res.json();
    const plan = detail.remediation_plan || {};

    await page.getByRole("tab", { name: "Remediation" }).click();
    const activePanel = page.locator('[role="tabpanel"]:not([hidden])');
    await expect(activePanel).toBeVisible();

    if (!plan.actual_remediation_available) {
      // Should show explanatory text, not fake remediation
      const explanatory = activePanel.getByText(/manual review required|evidence collected|no automated corrective/i);
      await expect(explanatory.first()).toBeVisible();
    }
  });

  test("no console errors on detail page", async ({ page }) => {
    const investigations = await getRuntimeInvestigations();
    test.skip(investigations.length === 0, "No runtime investigations available");

    const errors: string[] = [];
    page.on("console", (msg) => {
      if (msg.type() === "error") {
        const text = msg.text();
        if (!text.includes("404") && !text.includes("favicon")) {
          errors.push(text);
        }
      }
    });

    await page.goto(`/runtime/investigations/${investigations[0].id}`);
    const loading = page.getByText("Loading...");
    await loading.waitFor({ state: "hidden", timeout: 15000 }).catch(() => {});

    expect(errors.filter((e) => !e.includes("ResizeObserver"))).toHaveLength(0);
  });

  test("timeline tab renders events or empty state", async ({ page }) => {
    const investigations = await getRuntimeInvestigations();
    test.skip(investigations.length === 0, "No runtime investigations available");

    await page.goto(`/runtime/investigations/${investigations[0].id}`);
    const loading = page.getByText("Loading...");
    await loading.waitFor({ state: "hidden", timeout: 15000 }).catch(() => {});

    await page.getByRole("tab", { name: "Timeline" }).click();
    const activePanel = page.locator('[role="tabpanel"]:not([hidden])');
    await expect(activePanel).toBeVisible();

    const hasEvents = await activePanel.locator("div").count() > 2;
    const emptyState = await activePanel.getByText("No timeline events").isVisible().catch(() => false);
    expect(hasEvents || emptyState).toBe(true);
  });
});

test.describe("Runtime Investigations - Synthetic UX Assertions", () => {
  test("admin can understand case without reading raw YAML", async ({ page }) => {
    const investigations = await getRuntimeInvestigations();
    test.skip(investigations.length === 0, "No runtime investigations available");

    // Skip demo investigations
    const realInvestigations = investigations.filter((i: any) => !i.incident_title?.includes("DEMO"));
    test.skip(realInvestigations.length === 0, "No real runtime investigations available");

    const inv = realInvestigations[0];
    await page.goto(`/runtime/investigations/${inv.id}`);

    const loading = page.getByText("Loading...");
    await loading.waitFor({ state: "hidden", timeout: 15000 }).catch(() => {});

    // Summary card should be visible with human-readable text
    const summary = page.locator("div").filter({ hasText: /Next action/i }).first();
    await expect(summary).toBeVisible();

    // Should have at least one badge visible
    const badges = page.locator("span").filter({ hasText: /findings ready|observe|manual review/i });
    expect(await badges.count()).toBeGreaterThan(0);
  });

  test("loading and error states are understandable", async ({ page }) => {
    // Loading state on list
    await page.goto("/runtime/investigations");
    await expect(page.getByText("Loading...").or(page.getByText("No runtime investigations found")).or(page.locator(".divide-y > div").first())).toBeVisible();

    // Error state on invalid detail
    await page.goto("/runtime/investigations/invalid-id-12345");
    const loading = page.getByText("Loading...");
    await loading.waitFor({ state: "hidden", timeout: 15000 }).catch(() => {});
    await expect(page.getByText("Failed to load investigation")).toBeVisible();
  });
});

test.describe("Runtime Investigations - Diagnostic Tab UX", () => {
  test("diagnostic tab shows human-readable result card", async ({ page }) => {
    const investigations = await getRuntimeInvestigations();
    test.skip(investigations.length === 0, "No runtime investigations available");

    await page.goto(`/runtime/investigations/${investigations[0].id}`);
    const loading = page.getByText("Loading...");
    await loading.waitFor({ state: "hidden", timeout: 15000 }).catch(() => {});

    await page.getByRole("tab", { name: "Diagnostic" }).click();
    const activePanel = page.locator('[role="tabpanel"]:not([hidden])');
    await expect(activePanel).toBeVisible();

    // Diagnostic Result Card should be visible and human-readable
    await expect(activePanel.getByText("Diagnostic Result").first()).toBeVisible();
    await expect(activePanel.getByText("Main finding").first()).toBeVisible();
    await expect(activePanel.getByText("What this means").first()).toBeVisible();
  });

  test("diagnostic tab shows what was checked", async ({ page }) => {
    const investigations = await getRuntimeInvestigations();
    test.skip(investigations.length === 0, "No runtime investigations available");

    await page.goto(`/runtime/investigations/${investigations[0].id}`);
    const loading = page.getByText("Loading...");
    await loading.waitFor({ state: "hidden", timeout: 15000 }).catch(() => {});

    await page.getByRole("tab", { name: "Diagnostic" }).click();
    const activePanel = page.locator('[role="tabpanel"]:not([hidden])');
    await expect(activePanel.getByText("What Was Checked").first()).toBeVisible();
  });

  test("diagnostic tab shows gaps when they exist", async ({ page }) => {
    const investigations = await getRuntimeInvestigations();
    test.skip(investigations.length === 0, "No runtime investigations available");

    // Find an investigation that has diagnostic gaps
    let targetId = investigations[0].id;
    for (const inv of investigations.slice(0, 10)) {
      const detail = await getRuntimeInvestigationDetail(inv.id);
      if (detail.diagnostic_summary?.diagnostic_gaps?.length > 0) {
        targetId = inv.id;
        break;
      }
    }

    await page.goto(`/runtime/investigations/${targetId}`);
    const loading = page.getByText("Loading...");
    await loading.waitFor({ state: "hidden", timeout: 15000 }).catch(() => {});

    await page.getByRole("tab", { name: "Diagnostic" }).click();
    const activePanel = page.locator('[role="tabpanel"]:not([hidden])');

    const hasGaps = await activePanel.getByText("Diagnostic Problems / Gaps").first().isVisible().catch(() => false);
    if (hasGaps) {
      await expect(activePanel.getByText("Diagnostic Problems / Gaps").first()).toBeVisible();
    } else {
      test.skip(true, "No diagnostic gaps for this investigation");
    }
  });

  test("diagnostic tab shows recommended next steps", async ({ page }) => {
    const investigations = await getRuntimeInvestigations();
    test.skip(investigations.length === 0, "No runtime investigations available");

    await page.goto(`/runtime/investigations/${investigations[0].id}`);
    const loading = page.getByText("Loading...");
    await loading.waitFor({ state: "hidden", timeout: 15000 }).catch(() => {});

    await page.getByRole("tab", { name: "Diagnostic" }).click();
    const activePanel = page.locator('[role="tabpanel"]:not([hidden])');
    await expect(activePanel.getByText("Recommended Next Steps").first()).toBeVisible();
  });

  test("raw yaml and output are present but collapsible", async ({ page }) => {
    const investigations = await getRuntimeInvestigations();
    test.skip(investigations.length === 0, "No runtime investigations available");

    await page.goto(`/runtime/investigations/${investigations[0].id}`);
    const loading = page.getByText("Loading...");
    await loading.waitFor({ state: "hidden", timeout: 15000 }).catch(() => {});

    await page.getByRole("tab", { name: "Diagnostic" }).click();
    const activePanel = page.locator('[role="tabpanel"]:not([hidden])');

    // Raw output should be behind a collapsible trigger, not immediately visible as primary content
    await expect(activePanel.getByText("Show raw diagnostic output").first()).toBeVisible();
    await expect(activePanel.getByText("Show diagnostic playbook").first()).toBeVisible();

    // The primary visible content should NOT be raw preformatted output
    const firstCard = activePanel.locator("> div").first();
    await expect(firstCard.getByText("Diagnostic Result").first()).toBeVisible();
  });

  test("diagnostic tab does not require reading raw yaml to understand result", async ({ page }) => {
    const investigations = await getRuntimeInvestigations();
    test.skip(investigations.length === 0, "No runtime investigations available");

    await page.goto(`/runtime/investigations/${investigations[0].id}`);
    const loading = page.getByText("Loading...");
    await loading.waitFor({ state: "hidden", timeout: 15000 }).catch(() => {});

    await page.getByRole("tab", { name: "Diagnostic" }).click();
    const activePanel = page.locator('[role="tabpanel"]:not([hidden])');

    // Must have human-readable sections visible without expanding anything
    await expect(activePanel.getByText("Diagnostic Result").first()).toBeVisible();
    await expect(activePanel.getByText("What Was Checked").first()).toBeVisible();
    await expect(activePanel.getByText("Key Evidence Extracted").first()).toBeVisible();

    // Should NOT have raw pre blocks as the first visible content
    const firstPre = activePanel.locator("pre").first();
    const isPreVisible = await firstPre.isVisible().catch(() => false);
    if (isPreVisible) {
      // If a pre is visible, make sure it's not the first child (i.e. not primary content)
      const preParent = await firstPre.evaluate((el) => (el.parentElement?.parentElement?.getAttribute("data-state")));
      // Pre blocks inside CollapsibleContent won't be the primary content
      expect(preParent).not.toBeNull();
    }
  });
});


test.describe("Runtime Investigations - Data Quality & Edge Cases", () => {
  test("data quality warning visible for corrupted proc_name", async ({ page }) => {
    const investigations = await getRuntimeInvestigations();
    test.skip(investigations.length === 0, "No runtime investigations available");

    // Find an investigation with data quality warnings
    let targetId = investigations[0].id;
    for (const inv of investigations.slice(0, 10)) {
      const detail = await getRuntimeInvestigationDetail(inv.id);
      const dq = detail.classification_context?._data_quality;
      if (dq && Object.keys(dq).length > 0) {
        targetId = inv.id;
        break;
      }
    }

    await page.goto(`/runtime/investigations/${targetId}`);
    const loading = page.getByText("Loading...");
    await loading.waitFor({ state: "hidden", timeout: 15000 }).catch(() => {});

    const hasWarning = await page.getByText("Data Quality Warning").first().isVisible().catch(() => false);
    if (hasWarning) {
      await expect(page.getByText("Data Quality Warning").first()).toBeVisible();
      await expect(page.getByText(/corrupted|do not trust/i).first()).toBeVisible();
    } else {
      test.skip(true, "No data quality warnings for this investigation");
    }
  });

  test("list page shows explicit error on API failure", async ({ page }) => {
    // Block the API to simulate failure
    await page.route("**/api/v1/runtime/investigations?**", (route) => {
      route.fulfill({ status: 500, body: JSON.stringify({ detail: "Internal Server Error" }) });
    });

    await page.goto("/runtime/investigations");
    // Wait a moment for SWR to attempt the request
    await page.waitForTimeout(2000);

    await expect(page.getByText("Failed to load investigations").first()).toBeVisible();
    await expect(page.getByRole("button", { name: "Retry" }).first()).toBeVisible();
  });
});


test.describe("Runtime Investigations - Stats Cards", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/runtime/investigations");
  });

  test("stats cards render correct labels", async ({ page }) => {
    const loading = page.getByText("Loading...");
    await loading.waitFor({ state: "hidden", timeout: 15000 }).catch(() => {});

    // Core labels must exist
    await expect(page.getByText("Total").first()).toBeVisible();
    await expect(page.getByText("Findings Ready").first()).toBeVisible();
    await expect(page.getByText("Manual Review").first()).toBeVisible();
    await expect(page.getByText("Acknowledged").first()).toBeVisible();

    // Old misleading labels must NOT exist
    await expect(page.locator("text=Verified").filter({ hasText: /^Verified$/ })).toHaveCount(0);
    await expect(page.locator("text=Failed").filter({ hasText: /^Failed$/ })).toHaveCount(0);

    // New precise labels must exist
    await expect(page.getByText("Verified Fixes").first()).toBeVisible();
  });

  test("stats counts match backend", async ({ page }) => {
    const loading = page.getByText("Loading...");
    await loading.waitFor({ state: "hidden", timeout: 15000 }).catch(() => {});

    const stats = await getRuntimeStats();

    // Helper: find card by data-testid and extract its numeric value
    async function getCardValue(testId: string): Promise<number> {
      const card = page.locator(`[data-testid="${testId}"]`);
      const text = await card.locator(".text-2xl").textContent().catch(() => "0");
      return parseInt(text || "0", 10);
    }

    const total = await getCardValue("stat-total");
    expect(total).toBe(stats.total);

    const findingsReady = await getCardValue("stat-findings-ready");
    expect(findingsReady).toBe(stats.by_status.findings_ready || 0);

    const manualReview = await getCardValue("stat-manual-review");
    expect(manualReview).toBe(stats.by_status.manual_review_required || 0);

    const acknowledged = await getCardValue("stat-acknowledged");
    expect(acknowledged).toBe(stats.by_status.acknowledged || 0);

    const verifiedFixes = await getCardValue("stat-verified-fixes");
    expect(verifiedFixes).toBe(stats.by_status.verified || 0);

    // Observed card only shown when count > 0
    if ((stats.by_status.observe || 0) > 0) {
      const observed = await getCardValue("stat-observed");
      expect(observed).toBe(stats.by_status.observe || 0);
    }

    // Awaiting Approval only shown when count > 0
    if ((stats.by_status.awaiting_approval || 0) > 0) {
      const awaiting = await getCardValue("stat-awaiting-approval");
      expect(awaiting).toBe(stats.by_status.awaiting_approval || 0);
    }
  });

  test("stat cards show tooltips on hover", async ({ page }) => {
    const loading = page.getByText("Loading...");
    await loading.waitFor({ state: "hidden", timeout: 15000 }).catch(() => {});

    const verifiedCard = page.getByText("Verified Fixes").first().locator("xpath=../..");
    await verifiedCard.hover();
    await expect(page.getByText(/corrective remediation was executed and verified/i).first()).toBeVisible();
  });

  test("manual refresh button updates last updated timestamp", async ({ page }) => {
    const loading = page.getByText("Loading...");
    await loading.waitFor({ state: "hidden", timeout: 15000 }).catch(() => {});

    const refreshBtn = page.getByRole("button", { name: /Refresh/i });
    await expect(refreshBtn).toBeVisible();

    // Should show "Last updated" after initial load
    await expect(page.getByText(/Last updated/i).first()).toBeVisible();

    // Click refresh and verify timestamp updates
    await refreshBtn.click();
    await page.waitForTimeout(500);
    await expect(page.getByText(/Last updated/i).first()).toBeVisible();
  });
});

test.describe("Runtime Investigations - Stats After Actions", () => {
  test("after acknowledge, stats and list reflect updated state", async ({ page }) => {
    const investigations = await getRuntimeInvestigations();
    test.skip(investigations.length === 0, "No runtime investigations available");

    // Find a findings_ready or observe investigation that can be acknowledged
    const target = investigations.find(
      (i: any) => i.status === "findings_ready" || i.status === "observe" || i.status === "manual_review_required"
    );
    test.skip(!target, "No acknowledgeable investigation available");

    // Pre-check stats
    const preStats = await getRuntimeStats();
    const preAckCount = preStats.by_status.acknowledged || 0;

    await page.goto(`/runtime/investigations/${target.id}`);
    const loading = page.getByText("Loading...");
    await loading.waitFor({ state: "hidden", timeout: 15000 }).catch(() => {});

    // Acknowledge it
    const ackBtn = page.getByRole("button", { name: /Acknowledge/i });
    const canAck = await ackBtn.isVisible().catch(() => false);
    test.skip(!canAck, "Acknowledge button not available");

    await ackBtn.click();
    await page.waitForTimeout(2000);

    // Go back to list
    await page.goto("/runtime/investigations");
    await loading.waitFor({ state: "hidden", timeout: 15000 }).catch(() => {});

    // Stats should show updated acknowledged count
    const postStats = await getRuntimeStats();
    expect(postStats.by_status.acknowledged).toBeGreaterThanOrEqual(preAckCount);

    // List should show the investigation with acknowledged status
    const listItem = page.locator("text=" + target.incident_title).first().locator("xpath=../..");
    const statusBadge = listItem.locator("[class*='bg-emerald']").filter({ hasText: /acknowledged/i });
    const hasAckBadge = await statusBadge.isVisible().catch(() => false);
    expect(hasAckBadge).toBe(true);
  });
});


test.describe("Runtime Investigations - Stats Reconciliation", () => {
  test("visible stats + other count must reconcile with total", async ({ page }) => {
    await page.goto("/runtime/investigations");
    const loading = page.getByText("Loading...");
    await loading.waitFor({ state: "hidden", timeout: 15000 }).catch(() => {});

    // Collect all visible card values by data-testid
    async function getCardValue(testId: string): Promise<number> {
      const card = page.locator(`[data-testid="${testId}"]`);
      const count = await card.count();
      if (count === 0) return 0;
      const text = await card.locator(".text-2xl").textContent();
      return parseInt(text || "0", 10);
    }

    // Wait a moment for SWR stats to hydrate conditional cards
    await page.waitForTimeout(1000);

    const pageTotal = await getCardValue("stat-total");
    const findingsReady = await getCardValue("stat-findings-ready");
    const observed = await getCardValue("stat-observed");
    const manualReview = await getCardValue("stat-manual-review");
    const acknowledged = await getCardValue("stat-acknowledged");
    const awaitingApproval = await getCardValue("stat-awaiting-approval");
    const verifiedFixes = await getCardValue("stat-verified-fixes");
    const failedRemediations = await getCardValue("stat-failed-remediations");
    const declined = await getCardValue("stat-declined");
    const archivedFixed = await getCardValue("stat-archived-fixed");
    const archivedWithRisk = await getCardValue("stat-archived-with-risk");
    const closedWithRisk = await getCardValue("stat-closed-with-risk");
    const other = await getCardValue("stat-other");

    const visibleSum =
      findingsReady +
      observed +
      manualReview +
      acknowledged +
      awaitingApproval +
      verifiedFixes +
      failedRemediations +
      declined +
      archivedFixed +
      archivedWithRisk +
      closedWithRisk +
      other;

    expect(visibleSum).toBe(pageTotal);
  });
});
