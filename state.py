"""
state.py
─────────────────────────────────────────────────────────────────────────────
ARIA — Automated Resolution & Incident Agent
Shared state management — the single source of truth for each ticket.

Architecture role:
  The state dictionary is the only channel through which agents communicate.
  Agents do not call each other, share memory, or pass arguments between
  themselves. Each agent reads from defined input fields, writes to its own
  designated output section, and returns the updated state.

  This design eliminates:
    - Race conditions (each ticket gets its own isolated state object)
    - Tight coupling (agents are independently testable with mock state)
    - Implicit dependencies (all inter-agent data flow is explicit in state)

State lifecycle:
  build_initial_state() → Security → Intake → Diagnosis → Resolution
                        → [Escalation?] → final state returned to UI

Audit log contract:
  - Append-only — entries are never modified or deleted
  - Called by every agent after it completes
  - Records timestamp, event name, and detail string
  - Provides the immutable compliance trail (Wall 4 of security model)
─────────────────────────────────────────────────────────────────────────────
"""

from datetime import datetime, timezone
from mock_system import get_next_ticket_id


def build_initial_state(
    raw_input:   str,
    submitter:   str,
    employee_id: str,
) -> dict:
    """
    Constructs a fresh, fully-initialised state dictionary for a new ticket.

    Every ticket submission creates a completely independent state object.
    No state is shared between tickets — this is what prevents concurrent
    submissions from interfering with each other.

    All agent output fields are initialised to None. Downstream code should
    check for None before reading agent outputs to detect pipeline failures
    (e.g. an agent was skipped or errored before writing its section).

    Args:
        raw_input:   The unmodified ticket text as submitted by the user
        submitter:   Full name of the submitting employee
        employee_id: Employee ID string (e.g. "EMP-4821")

    Returns:
        Fully-initialised state dict ready for the Security agent
    """
    return {

        # ── Ticket identity ───────────────────────────────────────────────
        # Immutable after creation — agents must not modify these fields
        "ticket_id":    get_next_ticket_id(),              # e.g. TKT-001
        "submitter":    submitter,                         # "John Doe"
        "employee_id":  employee_id,                       # "EMP-4821"
        "submitted_at": datetime.now(timezone.utc).isoformat(),

        # ── Input fields ──────────────────────────────────────────────────
        # raw_input:    original submission — never modified by any agent
        # masked_input: PII-masked version — written by Security agent,
        #               used by all subsequent agents instead of raw_input
        "raw_input":    raw_input,
        "masked_input": None,

        # ── Security agent output ─────────────────────────────────────────
        # Written by: security_agent()
        # Read by:    pipeline.py (to decide whether to continue)
        "security": {
            "passed":             None,   # bool — True if all checks pass
            "injection_detected": None,   # bool — True if injection was found
            "pii_items_masked":   None,   # int  — count of PII items replaced
            "block_reason":       None,   # str  — human-readable block reason if failed
        },

        # ── Intake agent output ───────────────────────────────────────────
        # Written by: intake_agent()
        # Read by:    diagnosis_agent(), resolution_agent(), escalation_agent()
        "intake": {
            "severity":       None,   # str  — low | medium | high | critical
            "category":       None,   # str  — access | network | hardware | software | other
            "urgency_reason": None,   # str  — one sentence explaining severity choice
            "summary":        None,   # str  — clean one-line summary of the issue
        },

        # ── Diagnosis agent output ────────────────────────────────────────
        # Written by: diagnosis_agent()
        # Read by:    resolution_agent(), escalation_agent()
        # CRITICAL:   confidence value gates the Resolution agent's tool execution
        "diagnosis": {
            "root_cause":      None,   # str   — specific technical cause
            "affected_system": None,   # str   — exact system, service, or username
            "confidence":      None,   # float — 0.0 to 1.0 diagnostic certainty
            "reasoning":       None,   # str   — how the diagnosis was reached
        },

        # ── Resolution agent output ───────────────────────────────────────
        # Written by: resolution_agent()
        # Read by:    pipeline.py (to decide escalation), escalation_agent(), UI
        #
        # Tool chain design:
        #   A single ticket may require multiple sequential tool executions.
        #   Example: account locked + password expired → unlock_account THEN
        #   send_password_reset. tool_chain holds the ordered list of tools
        #   the LLM selected. tool_results holds one result dict per executed
        #   tool. Execution stops immediately if any tool in the chain fails —
        #   partial success is treated as failure and escalated to a human.
        "resolution": {
            "can_auto_fix": None,   # bool — LLM self-assessment of auto-fix viability
            "tool_chain":   None,   # list — ordered [{tool, arguments}, ...] max 3 steps
            "confidence":   None,   # float — LLM confidence in the full chain (0.0–1.0)
            "explanation":  None,   # str  — why each tool was selected and in what order
            "tool_results": None,   # list — one result dict per tool executed in chain
            "status":       None,   # str  — auto_resolved | escalated | failed
        },

        # ── Escalation agent output ───────────────────────────────────────
        # Written by: escalation_agent()
        # Read by:    UI (to display human handoff panel)
        # Only populated when resolution status is "escalated" or "failed"
        "escalation": {
            "team":     None,   # str — IT Support | Network Team | Hardware Team | Security Team
            "priority": None,   # str — low | medium | high | critical
            "summary":  None,   # str — two-sentence human-readable summary
            "context":  None,   # str — full diagnostic context for the receiving human agent
        },

        # ── Pipeline status ───────────────────────────────────────────────
        # Tracks overall ticket state as it moves through the pipeline.
        # Written by each agent after it completes.
        # Read by the Streamlit UI to update the agent pipeline status panel.
        #
        # Valid transitions:
        #   pending → secured → triaged → diagnosed →
        #   auto_resolved | escalated | failed | blocked
        "status": "pending",

        # ── Audit log ─────────────────────────────────────────────────────
        # Append-only list of timestamped events.
        # Written by: append_audit() called within each agent
        # Never modified or deleted — compliance immutability contract
        # Displayed in the Streamlit audit log panel
        "audit_log": [],
    }


def append_audit(state: dict, event: str, detail: str = "") -> dict:
    """
    Appends a timestamped entry to the ticket's audit log.

    Called at the end of every agent function to record what happened
    and when. This is Wall 4 of the security model — the immutable
    compliance trail that records every decision made during processing.

    Audit entries are never modified or deleted. The log is append-only
    by convention — no code in the system removes or edits entries.

    Args:
        state:  The shared state dict containing the audit_log list
        event:  Short event identifier (e.g. "intake_complete", "tool_executed")
        detail: Optional additional context (e.g. "severity: high · category: access")

    Returns:
        The updated state dict (allows chaining if needed)
    """
    state["audit_log"].append({
        "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
        "event":     event,
        "detail":    detail,
    })
    return state