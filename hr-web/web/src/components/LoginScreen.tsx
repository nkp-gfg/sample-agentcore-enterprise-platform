import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { BrandMark } from "@/components/BrandMark.tsx";

export function LoginScreen({
  error,
  onSignIn,
}: {
  error: string;
  onSignIn: () => void;
}) {
  return (
    <main className="flex min-h-svh items-center justify-center bg-background px-4 py-10">
      <Card className="w-full max-w-md shadow-none">
        <CardHeader className="gap-4">
          <BrandMark large />
          <div className="space-y-2">
            <p className="text-sm text-muted-foreground">Unified employee workspace</p>
            <CardTitle className="font-heading text-3xl tracking-tight">
              <h1>AgentCore Enterprise</h1>
            </CardTitle>
            <CardDescription className="text-sm leading-6 text-foreground/80">
              Sign in with your corporate account to work with HR operations,
              payroll, and finance. Decisions leave this page only when you
              press a card.
            </CardDescription>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <ul className="flex flex-wrap gap-2" aria-label="Workspace capabilities">
            <li><Badge variant="secondary">Multi-agent handover</Badge></li>
            <li><Badge variant="secondary">A2UI cards</Badge></li>
            <li><Badge variant="secondary">Policy guardrails</Badge></li>
          </ul>
          {error ? (
            <p role="alert" className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-900">
              {error}
            </p>
          ) : null}
          <Button type="button" size="lg" className="h-10 w-full" onClick={onSignIn}>
            Sign in
          </Button>
        </CardContent>
        <CardFooter className="text-xs text-muted-foreground">
          Secured with Amazon Cognito and Bedrock AgentCore
        </CardFooter>
      </Card>
    </main>
  );
}

export function SessionCheck() {
  return (
    <main className="flex min-h-svh items-center justify-center bg-background px-4">
      <div className="flex items-center gap-3 text-sm text-muted-foreground">
        <BrandMark />
        <p>Checking your session</p>
      </div>
    </main>
  );
}
