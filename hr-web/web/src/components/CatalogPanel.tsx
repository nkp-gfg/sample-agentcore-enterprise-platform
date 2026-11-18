import { useEffect, useState, useSyncExternalStore } from "react";
import { A2uiSurface } from "@a2ui/react";
import { toast } from "sonner";
import { GALLERY, galleryAckUpdate, type GallerySpecimen } from "@/a2ui/gallery.ts";
import { HrSurfaces } from "@/a2ui/surfaces.ts";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";

export function CatalogPanel() {
  const [specimenId, setSpecimenId] = useState(GALLERY[0]?.id ?? "");
  const [surfaces] = useState(() => {
    const created = new HrSurfaces((action) => {
      if (action.name !== "gallery_ack") {
        toast.message("Sample only. This button does not submit or approve.");
        return;
      }
      created.apply([galleryAckUpdate()]);
      toast.success("Card updated locally.");
    });
    created.apply(GALLERY.flatMap((item) => item.messages));
    return created;
  });

  useEffect(() => {
    return () => {
      surfaces.dispose();
    };
  }, [surfaces]);

  const version = useSyncExternalStore(
    surfaces.subscribe,
    surfaces.getVersion,
    surfaces.getVersion,
  );
  const specimen = GALLERY.find((item) => item.id === specimenId) ?? GALLERY[0];

  return (
    <div className="grid min-h-0 flex-1 grid-rows-[auto_minmax(0,1fr)] lg:grid-cols-[16rem_minmax(0,1fr)] lg:grid-rows-1">
      <nav className="flex gap-2 overflow-x-auto border-b p-3 lg:flex-col lg:overflow-y-auto lg:border-r lg:border-b-0" aria-label="Catalog specimens">
        {GALLERY.map((item) => (
          <button
            key={item.id}
            type="button"
            className={cn(
              "shrink-0 rounded-lg px-3 py-2 text-left text-sm",
              item.id === specimen?.id ? "bg-primary text-primary-foreground" : "hover:bg-muted",
            )}
            onClick={() => setSpecimenId(item.id)}
          >
            {item.title}
          </button>
        ))}
      </nav>
      {specimen ? <Specimen specimen={specimen} surfaces={surfaces} version={version} /> : null}
    </div>
  );
}

function Specimen({
  specimen,
  surfaces,
  version,
}: {
  specimen: GallerySpecimen;
  surfaces: HrSurfaces;
  version: number;
}) {
  const surfaceId = surfaceIdOf(specimen);
  const surface = surfaceId ? surfaces.get(surfaceId) : undefined;
  return (
    <ScrollArea className="min-h-0">
      <div className="mx-auto flex w-full max-w-3xl flex-col gap-4 px-4 py-6" data-revision={version}>
        <div className="space-y-1">
          <h2 className="font-heading text-2xl tracking-tight">{specimen.title}</h2>
          <p className="text-sm leading-6 text-muted-foreground">{specimen.blurb}</p>
        </div>
        <div className="a2-surface rounded-xl border bg-card p-4" data-surface={surfaceId}>
          {surface ? <A2uiSurface surface={surface} /> : (
            <p className="text-sm text-muted-foreground">This sample did not render.</p>
          )}
        </div>
        <details className="rounded-xl border bg-muted/40 p-3">
          <summary className="cursor-pointer text-sm font-medium">Wire</summary>
          <pre className="mt-3 overflow-x-auto font-mono text-[11px] leading-5">
            {JSON.stringify(specimen.messages, null, 2)}
          </pre>
        </details>
      </div>
    </ScrollArea>
  );
}

function surfaceIdOf(specimen: GallerySpecimen): string {
  const first = specimen.messages[0];
  if (!first || typeof first !== "object") return "";
  const createSurface = (first as { createSurface?: { surfaceId?: string } }).createSurface;
  return createSurface?.surfaceId ?? "";
}
