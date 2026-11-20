import { ThemeProvider } from "next-themes";
import { LoginScreen, SessionCheck } from "@/components/LoginScreen.tsx";
import { WorkspaceScreen } from "@/components/WorkspaceScreen.tsx";
import { Toaster } from "@/components/ui/sonner.tsx";
import { TooltipProvider } from "@/components/ui/tooltip.tsx";
import { useWorkspace } from "@/workspace/useWorkspace.ts";

export default function App() {
  const workspace = useWorkspace();
  return (
    <ThemeProvider forcedTheme="light" attribute="class" enableSystem={false}>
      <TooltipProvider>
        {workspace.status === "loading" ? <SessionCheck /> : null}
        {workspace.status === "anonymous" ? (
          <LoginScreen error={workspace.loginError} onSignIn={workspace.signIn} />
        ) : null}
        {workspace.status === "ready" ? <WorkspaceScreen workspace={workspace} /> : null}
        <Toaster position="top-right" />
      </TooltipProvider>
    </ThemeProvider>
  );
}
