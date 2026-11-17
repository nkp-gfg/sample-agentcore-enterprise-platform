import { useEffect, useMemo, useState, useSyncExternalStore } from "react";
import ReactMarkdown from "react-markdown";
import { Ellipsis, History, LogOut, Plus, RefreshCw } from "lucide-react";
import { toast } from "sonner";
import { A2uiSurface } from "@a2ui/react";
import { BrandMark } from "@/components/BrandMark.tsx";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Textarea } from "@/components/ui/textarea";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import type { HrSurfaces } from "@/a2ui/surfaces.ts";
import type { ThreadSummary } from "@/lib/bff.ts";
import { useWorkspace, type ChatMessage } from "@/workspace/useWorkspace.ts";

const STARTERS = [
  {
    title: "Leave balance",
    detail: "Check remaining annual and sick days",
    prompt: "How many annual and sick leave days do I have remaining?",
  },
  {
    title: "Telephone allowance",
    detail: "View the 2026-10 payroll allowance",
    prompt: "What was my telephone allowance for 2026-10?",
  },
  {
    title: "Team and compensation",
    detail: "List one-hop direct reports and salary",
    prompt: "Who are my direct reports, and what is my current compensation?",
  },
  {
    title: "Request leave",
    detail: "Open confirmation and manager review cards",
    prompt: "Submit annual leave from 2026-12-01 to 2026-12-03 for a family trip",
  },
] as const;

const PROMPT_MAX = 4000;

function initials(label: string): string {
  const parts = label.split(/[\s.@]+/).filter(Boolean);
  const first = parts[0] ?? "You";
  const second = parts[1];
  if (!second) return first.slice(0, 2).toUpperCase();
  return `${first[0] ?? ""}${second[0] ?? ""}`.toUpperCase();
}

function formatTime(timestamp: number): string {
  try {
    return new Date(timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  } catch {
    return "";
  }
}

function formatRelativeTime(timestamp: number): string {
  if (!timestamp) return "";
  const diffSec = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
  if (diffSec < 60) return "just now";
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  try {
    return new Date(timestamp).toLocaleDateString([], { month: "short", day: "numeric" });
  } catch {
    return "";
  }
}

function SurfaceColumn({ surfaces }: { surfaces: HrSurfaces }) {
  const version = useSyncExternalStore(surfaces.subscribe, surfaces.getVersion, surfaces.getVersion);
  const ids = surfaces.ids();
  return (
    <aside className="flex min-h-0 flex-col border-t bg-muted/40 lg:border-t-0 lg:border-l" aria-label="Interactive cards">
      <div className="flex items-baseline justify-between px-4 py-3">
        <h2 className="font-heading text-base font-medium">Cards</h2>
        <p className="text-xs text-muted-foreground" data-revision={version}>
          {ids.length === 0 ? "Waiting for a result" : `${ids.length} open`}
        </p>
      </div>
      <Separator />
      <ScrollArea className="min-h-0 flex-1">
        <div className="flex flex-col gap-3 p-4">
          {ids.length === 0 ? (
            <p className="text-sm leading-6 text-muted-foreground">
              Leave balances, allowances, reports, and review cards show up here.
              Typing a decision in the chat does not approve or reject anything.
            </p>
          ) : ids.map((id) => {
            const surface = surfaces.get(id);
            if (!surface) return null;
            return (
              <div key={id} data-surface={id} className="a2-surface">
                <A2uiSurface surface={surface} />
              </div>
            );
          })}
        </div>
      </ScrollArea>
    </aside>
  );
}

function MessageBody({ message }: { message: ChatMessage }) {
  if (message.role === "assistant" && message.text && !message.pending) {
    return (
      <div className="hr-md text-sm leading-6">
        <ReactMarkdown>{message.text}</ReactMarkdown>
      </div>
    );
  }
  return <p className="whitespace-pre-wrap text-sm leading-6">{message.text}</p>;
}

export function WorkspaceScreen({
  workspace,
}: {
  workspace: ReturnType<typeof useWorkspace>;
}) {
  const [draft, setDraft] = useState("");
  const [historyOpen, setHistoryOpen] = useState(false);
  const [historyQuery, setHistoryQuery] = useState("");
  const [historyError, setHistoryError] = useState("");

  useEffect(() => {
    const node = document.getElementById("chat-end");
    node?.scrollIntoView({ block: "end" });
  }, [workspace.messages, workspace.busy]);

  const filteredThreads = useMemo(() => {
    const query = historyQuery.trim().toLowerCase();
    if (!query) return workspace.threads;
    return workspace.threads.filter((thread) => thread.title.toLowerCase().includes(query));
  }, [historyQuery, workspace.threads]);

  async function loadHistory(open: boolean) {
    setHistoryOpen(open);
    if (!open) return;
    setHistoryError("");
    try {
      await workspace.refreshHistory();
    } catch (error) {
      const message = error instanceof Error ? error.message : "Could not load conversations.";
      setHistoryError(message);
      toast.error(message);
    }
  }

  async function removeThread(thread: ThreadSummary) {
    setHistoryError("");
    try {
      await workspace.removeThread(thread.threadId);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Could not delete that conversation.";
      setHistoryError(message);
      toast.error(message);
    }
  }

  async function clearHistory() {
    setHistoryError("");
    try {
      await workspace.removeAllThreads();
    } catch (error) {
      const message = error instanceof Error ? error.message : "Could not clear conversations.";
      setHistoryError(message);
      toast.error(message);
    }
  }

  function submit(text: string) {
    const message = text.trim();
    if (!message || workspace.busy) return;
    setDraft("");
    void workspace.sendMessage(message);
  }

  return (
    <div className="flex h-svh min-h-0 flex-col bg-background text-foreground">
      <header className="flex h-14 shrink-0 items-center gap-3 border-b bg-card px-3 sm:px-4">
        <BrandMark />
        <div className="min-w-0">
          <p className="truncate font-heading text-base leading-none font-medium">AgentCore Enterprise</p>
          <p className="mt-1 truncate text-xs text-muted-foreground">Unified employee workspace</p>
        </div>
        <Separator orientation="vertical" className="mx-1 hidden h-6 sm:block" />
        <div className="hidden min-w-0 items-center gap-2 sm:flex">
          <Avatar size="sm">
            <AvatarFallback>{initials(workspace.userLabel)}</AvatarFallback>
          </Avatar>
          <span className="max-w-48 truncate text-sm">{workspace.userLabel}</span>
        </div>
        <div className="ml-auto flex items-center gap-1.5">
          <Tooltip>
            <TooltipTrigger asChild>
              <Button type="button" variant="outline" disabled={workspace.busy} onClick={workspace.newChat}>
                <Plus />
                New chat
              </Button>
            </TooltipTrigger>
            <TooltipContent>Start a new conversation</TooltipContent>
          </Tooltip>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button type="button" variant="outline" onClick={() => void loadHistory(true)}>
                <History />
                History
              </Button>
            </TooltipTrigger>
            <TooltipContent>Open saved conversations</TooltipContent>
          </Tooltip>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                type="button"
                variant="ghost"
                disabled={workspace.busy}
                onClick={() => void workspace.refreshReviews()}
              >
                <RefreshCw />
                Reviews
                {workspace.reviewCount > 0 ? <Badge>{workspace.reviewCount}</Badge> : null}
              </Button>
            </TooltipTrigger>
            <TooltipContent>Check for pending manager reviews</TooltipContent>
          </Tooltip>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button type="button" variant="ghost" onClick={() => void workspace.signOut()}>
                <LogOut />
                Sign out
              </Button>
            </TooltipTrigger>
            <TooltipContent>End this session</TooltipContent>
          </Tooltip>
        </div>
      </header>

      <div className="grid min-h-0 flex-1 grid-rows-[minmax(0,1fr)_minmax(16rem,38vh)] lg:grid-cols-[minmax(0,1.15fr)_minmax(20rem,0.85fr)] lg:grid-rows-1">
        <section className="flex min-h-0 flex-col" aria-label="Conversation">
          <ScrollArea className="min-h-0 flex-1">
            <div className="mx-auto flex w-full max-w-3xl flex-col gap-4 px-4 py-6">
              {workspace.messages.length === 0 ? (
                <div className="space-y-5">
                  <div className="space-y-2">
                    <h1 className="font-heading text-3xl tracking-tight">Welcome to AgentCore Enterprise</h1>
                    <p className="max-w-xl text-sm leading-6 text-muted-foreground">
                      Ask about leave balances, eligibility, compensation, direct reports,
                      or monthly allowances. A card is the only way to confirm or approve.
                    </p>
                  </div>
                  <div className="grid gap-2 sm:grid-cols-2" role="list" aria-label="Starter prompts">
                    {STARTERS.map((starter) => (
                      <button
                        key={starter.title}
                        type="button"
                        disabled={workspace.busy}
                        className="rounded-xl border bg-card px-3 py-3 text-left transition-colors hover:bg-muted disabled:opacity-50"
                        onClick={() => submit(starter.prompt)}
                      >
                        <span className="block text-sm font-medium">{starter.title}</span>
                        <span className="mt-1 block text-sm text-muted-foreground">{starter.detail}</span>
                      </button>
                    ))}
                  </div>
                </div>
              ) : null}
              <div className="flex flex-col gap-3" aria-live="polite">
                {workspace.messages.map((message) => (
                  <article
                    key={message.id}
                    className={
                      message.role === "user"
                        ? "ml-auto max-w-[36rem] rounded-2xl bg-primary px-3.5 py-2.5 text-primary-foreground"
                        : message.role === "error"
                          ? "max-w-[40rem] rounded-xl border border-red-200 bg-red-50 px-3.5 py-2.5 text-red-950"
                          : message.role === "system"
                            ? "max-w-[40rem] text-sm text-muted-foreground"
                            : "max-w-[40rem] rounded-2xl bg-card px-3.5 py-2.5 ring-1 ring-border"
                    }
                  >
                    <div className="mb-1 flex items-baseline justify-between gap-3 text-[11px] opacity-70">
                      <span>{message.meta}</span>
                      <time dateTime={new Date(message.timestamp).toISOString()}>{formatTime(message.timestamp)}</time>
                    </div>
                    <MessageBody message={message} />
                    {message.traces.length > 0 ? (
                      <ul className="mt-2 space-y-1 border-t border-current/10 pt-2">
                        {message.traces.map((trace, index) => (
                          <li key={`${message.id}-trace-${index}`} className="text-xs">
                            <details>
                              <summary className="cursor-pointer">
                                {trace.kind === "deny" ? "Denied" : trace.kind === "allow" ? "Allowed" : "Tool"}
                                {" · "}
                                {trace.label}
                              </summary>
                              {trace.detail !== undefined ? (
                                <pre className="mt-1 overflow-x-auto whitespace-pre-wrap font-mono text-[11px]">
                                  {typeof trace.detail === "string"
                                    ? trace.detail
                                    : JSON.stringify(trace.detail, null, 2)}
                                </pre>
                              ) : null}
                            </details>
                          </li>
                        ))}
                      </ul>
                    ) : null}
                  </article>
                ))}
              </div>
              <div id="chat-end" />
            </div>
          </ScrollArea>

          <form
            className="border-t bg-card px-4 py-3"
            onSubmit={(event) => {
              event.preventDefault();
              submit(draft);
            }}
          >
            <div className="mx-auto flex w-full max-w-3xl flex-col gap-2">
              <label className="sr-only" htmlFor="chat-input">Message</label>
              <Textarea
                id="chat-input"
                value={draft}
                maxLength={PROMPT_MAX}
                rows={2}
                disabled={workspace.busy}
                placeholder='Ask about leave, your allowance, your reports. Typing "approve" does nothing — use the card.'
                onChange={(event) => setDraft(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" && !event.shiftKey) {
                    event.preventDefault();
                    submit(draft);
                  }
                }}
              />
              <div className="flex items-center justify-between gap-3 text-xs text-muted-foreground">
                <span>{draft.length} / {PROMPT_MAX}</span>
                <span className="hidden sm:inline">Enter to send. Shift+Enter for a new line.</span>
                <Button type="submit" disabled={workspace.busy || draft.trim().length === 0}>
                  Send
                </Button>
              </div>
            </div>
          </form>
          <footer className="flex items-center justify-between gap-3 border-t px-4 py-2 text-[11px] text-muted-foreground">
            <span className="truncate font-mono">session · {workspace.threadId || "—"}</span>
            <span className="hidden sm:inline">
              Identity stays on the server. Cards use A2UI v1.0.
            </span>
          </footer>
        </section>
        <SurfaceColumn surfaces={workspace.surfaces} />
      </div>

      <Sheet open={historyOpen} onOpenChange={(open) => void loadHistory(open)}>
        <SheetContent className="w-full data-[side=right]:sm:max-w-md">
          <SheetHeader>
            <SheetTitle>Conversation history</SheetTitle>
            <SheetDescription>Open a saved thread or remove it from this account.</SheetDescription>
          </SheetHeader>
          <div className="px-4">
            <label className="sr-only" htmlFor="history-search">Search conversations</label>
            <Input
              id="history-search"
              value={historyQuery}
              placeholder="Search conversations"
              onChange={(event) => setHistoryQuery(event.target.value)}
            />
          </div>
          {historyError ? (
            <p role="alert" className="px-4 text-sm text-red-800">{historyError}</p>
          ) : null}
          <ScrollArea className="min-h-0 flex-1 px-4">
            {filteredThreads.length === 0 ? (
              <p className="py-6 text-sm text-muted-foreground">No conversations yet.</p>
            ) : (
              <ul className="flex flex-col gap-1 pb-4">
                {filteredThreads.map((thread) => (
                  <li key={thread.threadId} className="flex items-start gap-1">
                    <button
                      type="button"
                      disabled={workspace.busy}
                      className="min-w-0 flex-1 rounded-lg px-2 py-2 text-left hover:bg-muted disabled:opacity-50"
                      onClick={() => {
                        setHistoryOpen(false);
                        void workspace.openThread(thread.threadId);
                      }}
                    >
                      <span className="block truncate text-sm font-medium">{thread.title}</span>
                      <span className="mt-0.5 block text-xs text-muted-foreground">
                        {formatRelativeTime(thread.updatedAt)}
                        {thread.messageCount ? ` · ${thread.messageCount} messages` : ""}
                      </span>
                    </button>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button type="button" variant="ghost" size="icon-sm" aria-label={`Actions for ${thread.title}`}>
                          <Ellipsis />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem variant="destructive" onClick={() => void removeThread(thread)}>
                          Delete
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </li>
                ))}
              </ul>
            )}
          </ScrollArea>
          <SheetFooter>
            <Button type="button" variant="outline" onClick={() => void clearHistory()} disabled={workspace.threads.length === 0}>
              Clear history
            </Button>
          </SheetFooter>
        </SheetContent>
      </Sheet>
    </div>
  );
}
