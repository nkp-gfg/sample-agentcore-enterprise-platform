import {
  Catalog,
  createFunctionImplementation,
  type FunctionImplementation,
} from "@a2ui/web_core/v1_0";
import {
  createComponentImplementation,
  type ReactCatalogComponent,
} from "@a2ui/react";
import catalogDocument from "./hr-catalog.json";
import { deriveDays, HR_VIEWS } from "./views.tsx";

export type HrCatalog = {
  id: string;
} & Record<string, unknown>;

function buildHrCatalog() {
  const schemas = Catalog.fromJson(catalogDocument as unknown as Record<string, unknown>);
  const components = [...schemas.components.entries()].map(([name, api]) => {
    const view = HR_VIEWS[name as keyof typeof HR_VIEWS];
    if (!view) {
      throw new Error(
        `hr-catalog.json declares ${name}, but the renderer does not draw it.`,
      );
    }
    return createComponentImplementation(api, view as never);
  });
  const functions = [...schemas.functions.entries()].map(([name, api]) => {
    if (name !== "deriveDays") {
      throw new Error(`hr-catalog.json declares ${name}(), and nothing here evaluates it.`);
    }
    return createFunctionImplementation(
      {
        name: api.name,
        returnType: api.returnType,
        schema: api.schema,
        description: api.description,
      },
      (args) => deriveDays(args),
    );
  });
  return schemas.withEntries(components, functions);
}

type BuiltCatalog = ReturnType<typeof buildHrCatalog>;

let catalog: BuiltCatalog | null = null;

export function hrCatalog(): BuiltCatalog {
  catalog ??= buildHrCatalog();
  return catalog;
}

export type { FunctionImplementation, ReactCatalogComponent };
