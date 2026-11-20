import {
  MessageProcessor,
  type ActionPayload,
  type RendererErrorMessage,
} from "@a2ui/web_core/v1_0";
import type { ReactCatalogComponent } from "@a2ui/react";
import { hrCatalog } from "./catalog.ts";

export class HrSurfaces {
  readonly processor: MessageProcessor<ReactCatalogComponent>;
  private version = 0;
  private readonly listeners = new Set<() => void>();
  private unsent: RendererErrorMessage[] = [];
  disposed = false;

  constructor(onAction: (action: ActionPayload) => void) {
    this.processor = new MessageProcessor(
      [hrCatalog() as unknown as MessageProcessor<ReactCatalogComponent>["catalogs"][number]],
      onAction,
      {
        reportErrorsOnly: true,
        errorHandler: (error) => this.noteError(error),
      },
    );
    this.processor.onSurfaceCreated(() => this.bump());
    this.processor.onSurfaceDeleted(() => this.bump());
  }

  apply(messages: readonly unknown[]): void {
    if (this.disposed || messages.length === 0) return;
    for (const message of messages) {
      for (const error of this.processor.processMessagesWithErrors([message])) {
        this.noteError(error);
      }
    }
    this.bump();
  }

  ids(): string[] {
    return [...this.processor.getSurfaces().keys()];
  }

  get(id: string) {
    return this.processor.getSurface(id);
  }

  takeErrors(): RendererErrorMessage[] {
    const out = this.unsent;
    this.unsent = [];
    return out;
  }

  capabilities(): unknown {
    return this.processor.getRendererCapabilities({ versions: ["1.0"] });
  }

  clear(): void {
    const deletions = this.ids().map((surfaceId) => ({
      version: "1.0",
      deleteSurface: { surfaceId },
    }));
    this.apply(deletions);
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.processor.dispose();
    this.listeners.clear();
  }

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  getVersion = (): number => this.version;

  private noteError(error: RendererErrorMessage): void {
    const code = error.error.code;
    const message = error.error.message;
    if (this.unsent.some((item) => item.error.code === code && item.error.message === message)) {
      return;
    }
    this.unsent.push(error);
    if (this.unsent.length > 20) this.unsent.shift();
  }

  private bump(): void {
    this.version += 1;
    for (const listener of this.listeners) listener();
  }
}

export type { ActionPayload };
