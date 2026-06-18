import { ThemeProvider } from "@/components/theme-provider";
import { WebSocketProvider } from "@/lib/websocket";
import { AppSidebar } from "@/components/app-sidebar";
import { PageTransition } from "@/components/page-transition";
import { Toaster } from "@/components/ui/toaster";
import { SelectedAssetProvider } from "@/lib/asset-context";
import { GlobalAdminSecretDialog } from "@/components/global-admin-secret-dialog";
import { GlobalCommandMenu } from "@/components/global-command-menu";
import { AuthGuard } from "@/components/auth-guard";
import { cn } from "@/lib/utils";

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <ThemeProvider
      attribute="class"
      defaultTheme="dark"
      enableSystem
      disableTransitionOnChange
    >
      <AuthGuard>
        <WebSocketProvider>
          <SelectedAssetProvider>
            <div className={cn(
              "flex bg-background",
              "flex-col md:flex-row md:h-screen md:overflow-hidden"
            )}>
              <AppSidebar />
              <main className="flex-1 overflow-auto">
                <PageTransition>{children}</PageTransition>
              </main>
            </div>
            <Toaster />
            <GlobalAdminSecretDialog />
            <GlobalCommandMenu />
          </SelectedAssetProvider>
        </WebSocketProvider>
      </AuthGuard>
    </ThemeProvider>
  );
}
