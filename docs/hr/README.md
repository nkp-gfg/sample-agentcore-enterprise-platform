# HR assistant

Build spec for the employee assistant. Coding starts from these pages, not from a chat. Build infrastructure, then the agent, then the UI. The order and the verify command for each layer are in [phases.md](../../custom-app-plan/phases.md).

Decisions that are already locked, and the module graph, stay in the planning notes:

- [Review](../../custom-app-plan/review.md)
- [Modules and destroy order](../../custom-app-plan/phases.md)
- [God agent](../../custom-app-plan/god-agent.md)
- [Human review](../../custom-app-plan/human-review.md)
- [Production principles](../../custom-app-plan/production-principles.md)

If a planning note and a page in this folder disagree about a column, a tool field, or an error code, this folder wins. The planning notes still win on product rules: who may see a salary, probation, and pending leave.

## Read this order

| Page | What it fixes before anyone writes code |
|---|---|
| [Modules](modules.md) | Folders, `platform.yaml`, deploy, verify, destroy |
| [Schema](schema.md) | Tables, constraints, and the demo seed |
| [Policy](policy.md) | The authorization policy input document and the reason codes |
| [Tools](tools.md) | Gateway tool names, arguments, and responses |
| [Acceptance](acceptance.md) | The cases each module must pass, and the red-team set |

The six production rules, the verdict for each, and the page where each fix lives are in [production principles](../../custom-app-plan/production-principles.md).

The open questions in the review are already closed by their defaults: every role uses the direct-report rule, one hop only, no leave type during probation, and telephone allowance reads Postgres. A different answer means a spec change before the code change.

## What is not in v1

Skip-level reports, acting managers, a live finance API, deducting a balance when a manager approves, separate agent runtimes, a generic form renderer, and a hosted website. They are listed in the planning notes so they are not rebuilt by accident.
