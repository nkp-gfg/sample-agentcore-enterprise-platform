import { cn } from "@/lib/utils";

export function BrandMark({ large = false }: { large?: boolean }) {
  return (
    <span
      aria-hidden
      className={cn(
        "inline-flex shrink-0 items-center justify-center rounded-md bg-primary font-heading font-semibold text-primary-foreground",
        large ? "size-12 text-lg" : "size-8 text-[13px]",
      )}
    >
      AE
    </span>
  );
}
