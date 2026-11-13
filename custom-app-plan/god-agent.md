# God agent

Every request lands on one agent. That agent routes. It is not an HR agent, and it does not answer from its own tools.

Checked against the LangChain docs on 2026-11-13:

- [Deep Agents subagents](https://docs.langchain.com/oss/python/deepagents/subagents)
- [Deep Agents customization](https://docs.langchain.com/oss/python/deepagents/customization)
- [Deep Agents human-in-the-loop](https://docs.langchain.com/oss/python/deepagents/human-in-the-loop)
- [Deep Agents permissions](https://docs.langchain.com/oss/python/deepagents/permissions)
- [Deep Agents AG-UI](https://docs.langchain.com/oss/python/deepagents/ag-ui)
- [LangGraph persistence](https://docs.langchain.com/oss/python/langgraph/persistence)
- [LangChain `create_agent`](https://docs.langchain.com/oss/python/langchain/overview)

## Three libraries, three jobs

| Library | Job in this assistant |
|---|---|
| Deep Agents | The god agent, and each department agent. `create_deep_agent` supplies the `task` tool. |
| LangGraph | The runtime under those agents: the checkpointer, `interrupt`, and `Command(resume=...)`. |
| LangChain | Each leaf. `create_agent` with one fixed tool set. |

The model stays `openai.gpt-oss-120b-1:0` through the `ChatBedrock` instance this platform already builds. The doc samples that name Gemini, Claude, or `eu.` profiles are not the model for this account.

## Why the middle agent is compiled

A dictionary subagent does not receive `SubAgentMiddleware`. Only the parent exposes `task`. A department agent written as a dictionary cannot call a sub-sub-agent.

A [`CompiledSubAgent`](https://docs.langchain.com/oss/python/deepagents/subagents#compiledsubagent) takes a graph that has already been compiled. `create_deep_agent` returns a LangGraph graph. Wrapping a department agent that way keeps that department agent's own `task` tool, which is how the third level exists.

```text
god agent                         create_deep_agent
  task → hr-operations            CompiledSubAgent, inner create_deep_agent
        task → leave-balance      create_agent, get_leave_balance
        task → leave-eligibility  create_agent, check_leave_eligibility
        task → leave-submit       create_agent, submit_leave_request
  task → hr-payroll               CompiledSubAgent, inner create_deep_agent
        task → compensation       create_agent, get_employee_compensation
        task → direct-reports     create_agent, list_direct_reports
  task → finance-payroll          CompiledSubAgent, inner create_deep_agent
        task → allowance          create_agent, get_allowance
```

`mode` is `isolated`. A department agent does not inherit the god agent's message history. Each `task` call starts that agent fresh, so the description on the call has to carry the question and the ids the parent already resolved.

The god agent's prompt tells it to route and then wait. It does not answer a salary, a balance, or an allowance itself. The department prompts do the same for their leaves.

## What the god agent must not have

Set `general_purpose_subagent=GeneralPurposeSubagentProfile(enabled=False)` on the harness profile. The default general-purpose subagent is added automatically and can see the parent's tools. Custom department agents stay, so `task` stays. The two-step "running without subagents" instructions are only for removing `task` entirely, which this agent does not do.

If a build still injects a general-purpose subagent, replace it with a subagent of that name that has no tools and a prompt that refuses the work. Acceptance is the same either way: the god agent cannot call the six gateway tools.

Filesystem writes are denied for `/**` with `FilesystemPermission(operations=["write"], paths=["/**"], mode="deny")`. That requires `deepagents>=0.5.2`. No sandbox backend, so there is no `execute` tool. Scratch state, if the harness requires a backend, is `StateBackend` only. Salary rows are not written into that scratch space.

Department agents and leaves do not inherit a host directory. Gateway tools live only on the leaf named for that tool.

## Checkpointer

Only the god agent is compiled with a checkpointer. The department graphs are compiled without one, so a pause belongs to the parent's thread and `Command(resume=...)` on that thread continues the leaf that paused.

H1 creates an empty database named `agent_state` on the same cluster. The agent does not create that database. It reads the name from SSM (`use-cases/hr-data/checkpoint-database`) and calls `PostgresSaver.setup()` to create the checkpoint tables. The import is `langgraph.checkpoint.postgres`. This is not the `hr` database and it is not `MemorySaver`. `MemorySaver` dies with the process. The runtime container is replaced. A review that can sit for a day has to be in Postgres.

`thread_id` is a UUID. `PostgresSaver` stores it in a bounded column. The stream call uses `durability="sync"`.

AgentCore Memory stays the platform memory for the verified `sub`. It is not the checkpointer for these interrupts.

## Where the code will go

Layer 2 redeploys module 6. The pattern is a new entry, `god-agent`, copied from `agent-code/agui-langgraph-agent` so AgentCore still proxies AG-UI SSE. Adding that name to `AGENT_PATTERNS` is part of layer 2, not a new stack. The sample `agui-langgraph-agent` stays the workshop pattern. The entry point accepts the same `prompt` and `runtimeSessionId` body the other patterns accept, and a decision for an open pause on that session.

Turning the god agent off is a redeploy of module 6 with the previous pattern.
