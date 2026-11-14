/* hr-web — A2UI v1.0 MessageProcessor.
 *
 * A tiny, no-build implementation of the v1.0 wire schema from
 * https://a2ui.org/specification/v1_0/ (createSurface, updateComponents,
 * updateDataModel, deleteSurface, action, error). The public surface matches
 * the shape ``@a2ui/web_core/v1_0`` exposes so a future swap to the upstream
 * SDK is a drop-in. See ui-primitives.md for the HR catalog it draws, and the
 * design note in hr-web/README.md for why this file exists instead of
 * importing the SDK over a CDN.
 *
 * Scope:
 *   - inbound agent → renderer messages:
 *     createSurface, updateComponents, updateDataModel, deleteSurface,
 *     agentFunctionResponse (accepted but ignored — this UI uses no tools);
 *     callRendererFunction is explicitly refused with a renderer error.
 *   - outbound renderer → agent messages:
 *     ``{version: "1.0", action: {...}}`` emitted when a Button action fires,
 *     ``{version: "1.0", error: {...}}`` for every rejected message.
 *   - data bindings:
 *     ``{"@path": "/x/y"}`` reads from the surface's data model;
 *     ``{"@call": "funcName", "args": {...}}`` calls a registered function.
 *
 * Non-goals (match the upstream SDK's scope but not this build):
 *   - checks / validations (zod schemas): the catalog JSON is a guardrail for
 *     the agent, not for this renderer; we don't want lit+zod in the browser.
 *   - signals (@preact/signals-core): we re-render the whole surface on
 *     updateComponents / updateDataModel, which is fine for a facilitator UI.
 *   - renderer function calls other than the ones registered in a catalog.
 *
 * Every refused message produces a renderer error for the parent app to ship
 * back to the agent on the next request's metadata, as the v1.0 renderer-
 * to-agent schema prescribes.
 */

(() => {
  "use strict";

  const PROTOCOL_VERSION = "1.0";
  const RENDERER_NAME = "hr-web/a2ui";

  const ERROR_CODES = Object.freeze({
    VERSION_MISMATCH: "VERSION_MISMATCH",
    UNKNOWN_MESSAGE: "UNKNOWN_MESSAGE",
    UNKNOWN_COMPONENT: "UNKNOWN_COMPONENT",
    UNKNOWN_SURFACE: "UNKNOWN_SURFACE",
    DUPLICATE_SURFACE: "DUPLICATE_SURFACE",
    BINDING_FAILED: "BINDING_FAILED",
    FUNCTION_REFUSED: "FUNCTION_REFUSED",
  });

  /* ------------------------------------------------- data model helpers */

  const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

  function _isSafeKey(key) {
    return typeof key === "string" && key.length > 0 && !FORBIDDEN_KEYS.has(key);
  }

  function _sanitizeClone(value) {
    if (value === null || typeof value !== "object") return value;
    if (Array.isArray(value)) return value.map((item) => _sanitizeClone(item));
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (!_isSafeKey(k)) continue;
      out[k] = _sanitizeClone(v);
    }
    return out;
  }

  function _splitPointer(pointer) {
    if (typeof pointer !== "string" || pointer.length === 0 || pointer === "/") {
      return [];
    }
    if (pointer[0] !== "/") throw new Error(`Bad JSON pointer: ${pointer}`);
    return pointer.slice(1).split("/").map((seg) =>
      seg.replaceAll("~1", "/").replaceAll("~0", "~"),
    );
  }

  function _getAtPath(root, pointer) {
    const parts = _splitPointer(pointer);
    let node = root;
    for (const p of parts) {
      if (node == null || typeof node !== "object") return undefined;
      if (!_isSafeKey(p) || !Object.prototype.hasOwnProperty.call(node, p)) return undefined;
      node = node[p];
    }
    return node;
  }

  function _setAtPath(root, pointer, value) {
    const parts = _splitPointer(pointer);
    if (parts.length === 0) {
      return value && typeof value === "object" && !Array.isArray(value)
        ? _sanitizeClone(value)
        : {};
    }
    const clone = root && typeof root === "object" && !Array.isArray(root)
      ? _sanitizeClone(root)
      : {};
    for (const seg of parts) {
      if (!_isSafeKey(seg)) return clone;
    }
    let node = clone;
    for (let i = 0; i < parts.length - 1; i += 1) {
      const key = parts[i];
      if (!Object.prototype.hasOwnProperty.call(node, key) || node[key] == null || typeof node[key] !== "object") {
        node[key] = {};
      }
      node = node[key];
    }
    const last = parts[parts.length - 1];
    if (value === null) delete node[last];
    else node[last] = _sanitizeClone(value);
    return clone;
  }

  /* ------------------------------------------------- binding resolver */

  function resolveBinding(value, model, functions) {
    if (value === null || typeof value !== "object") return value;
    if (Array.isArray(value)) return value.map((v) => resolveBinding(v, model, functions));
    if (typeof value["@path"] === "string") {
      return _getAtPath(model, value["@path"]);
    }
    if (typeof value["@call"] === "string") {
      const fnName = value["@call"];
      if (!_isSafeKey(fnName) || !functions || !Object.prototype.hasOwnProperty.call(functions, fnName)) {
        return undefined;
      }
      const impl = functions[fnName];
      if (typeof impl !== "function") return undefined;
      const args = {};
      if (value.args && typeof value.args === "object") {
        for (const [k, v] of Object.entries(value.args)) {
          if (!_isSafeKey(k)) continue;
          args[k] = resolveBinding(v, model, functions);
        }
      }
      try {
        return impl(args);
      } catch (_err) {
        return undefined;
      }
    }
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (!_isSafeKey(k)) continue;
      out[k] = resolveBinding(v, model, functions);
    }
    return out;
  }

  /* ------------------------------------------------- Surface model */

  class SurfaceModel {
    constructor(surfaceId, catalogId) {
      this.surfaceId = surfaceId;
      this.catalogId = catalogId || "";
      this.sendDataModel = false;
      this.components = new Map(); // id -> {component, properties}
      this.dataModel = {};
    }

    setComponents(list) {
      this.components.clear();
      for (const spec of list) {
        if (!spec || typeof spec !== "object" || typeof spec.id !== "string") continue;
        const { id, component, ...rest } = spec;
        this.components.set(id, {
          id,
          component: typeof component === "string" ? component : "Text",
          properties: rest,
        });
      }
    }

    getComponent(id) {
      return this.components.get(id);
    }
  }

  /* ------------------------------------------------- MessageProcessor */

  class MessageProcessor {
    /**
     * @param {object} options
     * @param {object} options.catalog           { components: {Name: fn}, functions?: {name: fn} }
     * @param {HTMLElement} options.root          surfaces mount point
     * @param {(msg: object) => void} options.onRendererMessage
     *        called with each renderer→agent message (action or error).
     * @param {(id: string, prev?: HTMLElement) => void} [options.onSurfaceRendered]
     * @param {string} [options.protocolVersion]  the version this renderer accepts
     */
    constructor({ catalog, root, onRendererMessage, onSurfaceRendered, protocolVersion }) {
      if (!catalog || typeof catalog.components !== "object") {
        throw new Error("A2UI MessageProcessor needs a catalog with components.");
      }
      if (!(root instanceof HTMLElement)) {
        throw new Error("A2UI MessageProcessor needs a root HTMLElement.");
      }
      this.catalog = catalog;
      this.root = root;
      this.onRendererMessage = typeof onRendererMessage === "function"
        ? onRendererMessage
        : () => {};
      this.onSurfaceRendered = typeof onSurfaceRendered === "function"
        ? onSurfaceRendered
        : () => {};
      this.protocolVersion = protocolVersion || PROTOCOL_VERSION;
      /** @type {Map<string, SurfaceModel>} */
      this.surfaces = new Map();
      /** @type {Map<string, HTMLElement>} */
      this.surfaceNodes = new Map();
      /** Errors not yet reported to the agent. */
      this.pendingErrors = [];
    }

    /* ---- public SDK-shaped surface ---- */

    processMessages(messages) {
      const errors = [];
      if (!Array.isArray(messages)) return errors;
      for (const message of messages) {
        const err = this._processOne(message);
        if (err) errors.push(err);
      }
      return errors;
    }

    getSurface(id) {
      return this.surfaces.get(id);
    }

    getSurfaces() {
      return this.surfaces;
    }

    clear() {
      for (const id of [...this.surfaces.keys()]) {
        this._deleteSurface(id);
      }
    }

    takeErrors() {
      const out = this.pendingErrors;
      this.pendingErrors = [];
      return out;
    }

    /** Capabilities this renderer advertises, per the v1.0 schema. */
    getRendererCapabilities() {
      return {
        name: RENDERER_NAME,
        protocolVersions: [this.protocolVersion],
        catalogs: [this.catalog.catalogId || RENDERER_NAME],
      };
    }

    /* ---- message handlers ---- */

    _processOne(message) {
      if (!message || typeof message !== "object") {
        return this._reportError(ERROR_CODES.UNKNOWN_MESSAGE, "Message is not an object.", {});
      }
      if (message.version !== this.protocolVersion) {
        return this._reportError(
          ERROR_CODES.VERSION_MISMATCH,
          `Expected A2UI v${this.protocolVersion}, got ${JSON.stringify(message.version)}.`,
          {},
        );
      }
      if (message.createSurface) return this._createSurface(message.createSurface);
      if (message.updateComponents) return this._updateComponents(message.updateComponents);
      if (message.updateDataModel) return this._updateDataModel(message.updateDataModel);
      if (message.deleteSurface) return this._deleteSurface(message.deleteSurface.surfaceId);
      if (message.agentFunctionResponse) return null;  // ignored; we call no agent functions
      if (message.callRendererFunction) {
        return this._reportError(
          ERROR_CODES.FUNCTION_REFUSED,
          "This renderer executes no agent-called functions.",
          { surfaceId: message.callRendererFunction.surfaceId },
        );
      }
      return this._reportError(
        ERROR_CODES.UNKNOWN_MESSAGE,
        `Unknown A2UI message shape: keys=${Object.keys(message).join(",")}`,
        {},
      );
    }

    _createSurface(payload) {
      const id = payload.surfaceId;
      if (typeof id !== "string" || !id) {
        return this._reportError(ERROR_CODES.UNKNOWN_SURFACE, "createSurface needs a surfaceId.", {});
      }
      if (this.surfaces.has(id)) {
        return this._reportError(ERROR_CODES.DUPLICATE_SURFACE,
          `Surface ${id} already exists. Delete it first.`, { surfaceId: id });
      }
      const model = new SurfaceModel(id, payload.catalogId);
      model.sendDataModel = Boolean(payload.sendDataModel);
      if (payload.dataModel && typeof payload.dataModel === "object") {
        model.dataModel = _sanitizeClone(payload.dataModel);
      }
      if (Array.isArray(payload.components)) {
        model.setComponents(payload.components);
      }
      this.surfaces.set(id, model);
      return this._renderSurface(id);
    }

    _updateComponents(payload) {
      const id = payload.surfaceId;
      const model = this.surfaces.get(id);
      if (!model) {
        return this._reportError(ERROR_CODES.UNKNOWN_SURFACE,
          `updateComponents refers to unknown surface ${id}.`, { surfaceId: id });
      }
      if (Array.isArray(payload.components)) model.setComponents(payload.components);
      return this._renderSurface(id);
    }

    _updateDataModel(payload) {
      const id = payload.surfaceId;
      const model = this.surfaces.get(id);
      if (!model) {
        return this._reportError(ERROR_CODES.UNKNOWN_SURFACE,
          `updateDataModel refers to unknown surface ${id}.`, { surfaceId: id });
      }
      model.dataModel = _setAtPath(model.dataModel, payload.path || "/", payload.value);
      return this._renderSurface(id);
    }

    _deleteSurface(id) {
      const node = this.surfaceNodes.get(id);
      if (node && node.parentNode === this.root) this.root.removeChild(node);
      this.surfaceNodes.delete(id);
      this.surfaces.delete(id);
      return null;
    }

    /* ---- rendering ---- */

    _renderSurface(id) {
      const model = this.surfaces.get(id);
      if (!model) return null;
      const container = document.createElement("section");
      container.className = "a2ui-surface";
      container.dataset.surfaceId = id;
      container.dataset.catalogId = model.catalogId || "";
      const rootSpec = model.getComponent("root");
      if (!rootSpec) {
        container.append(document.createTextNode(""));
      } else {
        try {
          const node = this._renderComponent(model, "root");
          if (node) container.append(node);
        } catch (err) {
          this._reportError(ERROR_CODES.BINDING_FAILED,
            `Render failed on surface ${id}: ${err.message}`, { surfaceId: id });
          container.append(document.createTextNode(""));
        }
      }
      const prev = this.surfaceNodes.get(id);
      if (prev && prev.parentNode === this.root) {
        this.root.replaceChild(container, prev);
      } else {
        this.root.append(container);
      }
      this.surfaceNodes.set(id, container);
      this.onSurfaceRendered(id, container);
      return null;
    }

    _renderComponent(model, componentId) {
      const spec = model.getComponent(componentId);
      if (!spec) return null;
      const impl = this.catalog.components[spec.component];
      if (typeof impl !== "function") {
        this._reportError(ERROR_CODES.UNKNOWN_COMPONENT,
          `Catalog does not draw ${spec.component}.`,
          { surfaceId: model.surfaceId });
        const fallback = document.createElement("div");
        fallback.className = "a2ui-unknown";
        fallback.dataset.component = spec.component;
        return fallback;
      }
      const context = Object.freeze({
        surfaceId: model.surfaceId,
        componentId: spec.id,
        resolve: (value) => resolveBinding(value, model.dataModel, this.catalog.functions),
        getDataModel: () => JSON.parse(JSON.stringify(model.dataModel || {})),
        renderChild: (childId) => this._renderComponent(model, childId),
        emitAction: (event, context_) => {
          this._emitAction(model, spec.id, event, context_);
        },
      });
      return impl(spec.properties, context);
    }

    _emitAction(model, sourceComponentId, event, contextOverride) {
      if (!event || typeof event !== "object" || typeof event.name !== "string") return;
      const resolved = resolveBinding(event.context || {}, model.dataModel, this.catalog.functions) || {};
      const merged = contextOverride && typeof contextOverride === "object"
        ? { ...resolved, ...contextOverride }
        : resolved;
      const action = {
        name: event.name,
        surfaceId: model.surfaceId,
        sourceComponentId,
        timestamp: new Date().toISOString(),
        context: merged,
      };
      if (typeof event.userMessage === "string") action.userMessage = event.userMessage;
      this.onRendererMessage({ version: this.protocolVersion, action });
    }

    _reportError(code, message, extra) {
      const envelope = {
        version: this.protocolVersion,
        error: Object.assign({ code, message }, extra || {}),
      };
      this.pendingErrors.push(envelope);
      this.onRendererMessage(envelope);
      return envelope;
    }
  }

  /* ------------------------------------------------- module exports */

  window.A2UI = Object.freeze({
    MessageProcessor,
    PROTOCOL_VERSION,
    ERROR_CODES,
    resolveBinding,
    _internals: Object.freeze({
      getAtPath: _getAtPath,
      setAtPath: _setAtPath,
    }),
  });
})();
