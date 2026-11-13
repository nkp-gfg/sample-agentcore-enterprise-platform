# Human review

A review is a paused graph, not a sentence in the chat. The backend keeps the pause in Postgres. The frontend draws the pause and is the only thing that resumes it.

Checked against:

- [Deep Agents human-in-the-loop](https://docs.langchain.com/oss/python/deepagents/human-in-the-loop)
- [LangGraph interrupts](https://docs.langchain.com/oss/python/langgraph/interrupts)
- [Frontend human-in-the-loop](https://docs.langchain.com/oss/python/langchain/frontend/human-in-the-loop)
- [Deep Agents AG-UI](https://docs.langchain.com/oss/python/deepagents/ag-ui)
- [LangGraph checkpointers](https://docs.langchain.com/oss/python/langgraph/checkpointers)

## Two pauses

Both pauses use the god agent's thread. A subagent interrupt is delivered on the parent result as `__interrupt__`. The stream does not need `subgraphs=True` for that.

| Pause | Who may resume | Decisions | What has already been written |
|---|---|---|---|
| Employee confirmation | The employee on the thread | `approve`, `edit`, `reject` | Nothing. `interrupt_on` stops `submit_leave_request` before the Lambda runs. |
| Manager review | The direct manager of that employee | `approve`, `reject` | One `pending` row. The review node calls `interrupt()` and updates the row only after resume. |

`respond` is not an allowed decision. The docs treat `respond` as the human acting as the tool, and a model can read that message as a successful result.

Read tools are not in `interrupt_on`. `get_leave_balance`, `check_leave_eligibility`, `get_employee_compensation`, `list_direct_reports`, and `get_allowance` run without a card.

There is still no `approve_leave` tool. The manager's decision is the resume payload. The model cannot call it.

## Employee confirmation

The leave-submit leaf sets:

```python
interrupt_on={"submit_leave_request": {"allowed_decisions": ["approve", "edit", "reject"]}}
```

`approve` runs the tool with the proposed arguments. The Lambda still overwrites the caller from the token and still asks OPA. `edit` changes those arguments and then takes the same path, so a probation date or a longer range still comes back `PROBATION_PERIOD` or `INSUFFICIENT_BALANCE` and inserts nothing. `reject` does not call the Lambda. The tool message tells the leaf the request was not submitted.

The node that inserts the row does not also call `interrupt()`. On resume, LangGraph runs the node from the top again. An insert placed before `interrupt()` would run twice.

## Manager review

After the tool returns a `pending` request, the next node interrupts with a JSON payload:

| Field | Value |
|---|---|
| `kind` | `manager_review` |
| `request_id` | The pending row |
| `employee_id` | The requester |
| `reviewer_employee_id` | That employee's current `manager_id` |
| `leave_type`, `start_date`, `end_date`, `days` | The stored request |

No write happens before this `interrupt()`. After `Command(resume=...)` returns `approve`, one update sets `status` to `approved`, `decided_by` to the reviewer, and `decided_at`. `reject` sets `rejected` the same way. The balance is not reduced. A second resume sees the row is no longer `pending` and does not update it again.

The employee confirmation payload uses `kind: employee_confirm` and the same request fields, plus the proposed tool arguments.

## Who is allowed to resume

The runtime checks the token before it applies `Command`. The model does not.

| Payload `kind` | Required `employee_id` on the token |
|---|---|
| `employee_confirm` | The owner of the thread |
| `manager_review` | `reviewer_employee_id` on the payload |

Anyone else gets `NOT_REVIEWER` and the graph stays paused. That includes the employee trying to approve their own request, a peer, a skip-level manager, and a terminated manager. The pending row stays pending.

A chat message that says "approve" is a new user message. While an interrupt is open, the runtime does not start a new model turn for that thread. It returns the same interrupt.

## Frontend

This deployment does not add a LangSmith Agent Server. The existing AG-UI path on the runtime is the frontend protocol. `@ag-ui/langgraph` emits the interrupt when `emitInterruptOutcome` is true: `RUN_FINISHED` with `outcome.type === "interrupt"`. The client resumes by sending the AG-UI `resume` list on the same `threadId`. The runtime turns that list into `Command(resume=...)` only after the token check above.

The employee page shows a confirmation card for `employee_confirm`, then a waiting state for `manager_review`. The manager page lists paused reviews whose `reviewer_employee_id` is the signed-in manager and shows a card with approve and reject. Edit is only on the employee card.

The card is still there after a refresh and after the runtime container is replaced, because the checkpoint is in `agent_state`.

## Acceptance

| Case | Result |
|---|---|
| Eligible employee confirms | one `pending` row, balance unchanged |
| Employee rejects the card | no row |
| Employee types "approve" | no row, the card remains |
| Edited dates that fail OPA | no row, the reason code from the tool |
| Same key, second confirm | one row |
| Runtime restarted while the card is open | the same card returns |
| Direct manager approves | `approved`, `decided_by` is that manager, balance unchanged |
| Employee resumes the manager pause | `NOT_REVIEWER`, row stays `pending` |
| Skip-level manager resumes it | `NOT_REVIEWER` |
| Manager approves twice | still one decision |
