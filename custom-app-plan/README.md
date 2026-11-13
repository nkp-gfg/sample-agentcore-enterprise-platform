# HR assistant planning

Product decisions and the module graph. The pages an implementer codes from are under `docs/hr/`.

| Note | Use it for |
|---|---|
| [review.md](review.md) | Locked product rules, and where plan 1 and plan 2 were reconciled |
| [phases.md](phases.md) | Layer 1 CDK, layer 2 CLI agent, layer 3 UI, and destroy order |
| [god-agent.md](god-agent.md) | The one entry agent, its subagents, and the LangChain stack |
| [human-review.md](human-review.md) | Employee confirmation and manager review interrupts |

| Spec | Use it for |
|---|---|
| [docs/hr/README.md](../docs/hr/README.md) | The reading order |
| [docs/hr/modules.md](../docs/hr/modules.md) | Folders, `platform.yaml`, deploy, destroy |
| [docs/hr/schema.md](../docs/hr/schema.md) | Tables and the demo seed |
| [docs/hr/policy.md](../docs/hr/policy.md) | OPA input and reason codes |
| [docs/hr/tools.md](../docs/hr/tools.md) | Tool names, arguments, responses |
| [docs/hr/acceptance.md](../docs/hr/acceptance.md) | Tests each module must pass |

Do not start a module until the spec page for it is still accurate. A code change that needs a new column or a new reason code updates the spec in the same change.
