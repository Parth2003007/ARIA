"""
pipeline.py
─────────────────────────────────────────────────────────────────────────────
ARIA — Automated Resolution & Incident Agent
Pipeline controller — the sequencing layer between agents.

Architecture role:
  The pipeline controller is a pure Python function with no LLM calls,
  no UI logic, and no business logic. Its sole responsibility is to:
    1. Call agents in the correct order
    2. Pass state between them
    3. Implement conditional branching (escalation trigger)
    4. Return the final state to the caller (app.py)

  This separation means:
    - The pipeline can be tested independently with mock agents
    - Agents can be tested independently with mock state
    - The UI (app.py) never needs to know about agent sequencing
    - Adding a new agent requires changing only this file

Pipeline flow:
  Phase 1 — Security agent   (always runs, can terminate pipeline)
  Phase 2 — Intake agent     (always runs if security passes)
  Phase 3 — Diagnosis agent  (always runs if security passes)
  Phase 4 — Resolution agent (always runs if security passes)
  Phase 5 — Escalation agent (conditional — only runs if resolution
                               status is "escalated" or "failed")

Design note on sequential vs parallel execution:
  The pipeline is intentionally sequential. Each agent's output is a
  strict dependency for the next — Diagnosis needs Intake's category,
  Resolution needs Diagnosis's confidence score. True parallelism would
  require agents whose outputs are independent, which is not the case here.
  A sequential pipeline is simpler, produces clearer audit trails, and
  is easier to debug — all of which are priorities for an enterprise system.
─────────────────────────────────────────────────────────────────────────────
"""

from agents import (
    security_agent,
    intake_agent,
    diagnosis_agent,
    resolution_agent,
    escalation_agent,
)
from state import build_initial_state

def enrich_with_system_context(state: dict) -> dict:
    """
    Queries the mock system for live context before Diagnosis runs.
    In production this would call real monitoring APIs.
    Gives the Diagnosis agent real data, not just the user's description.
    """
    category        = state["intake"]["category"]
    affected_system = state["intake"]["summary"]  # rough hint from Intake

    context = {}

    # If it's a network/service ticket — check service statuses
    if category == "network":
        context["services"] = {}
        for svc_name, svc_info in SYSTEM_STATE["services"].items():
            if svc_info["status"] != "running":
                context["services"][svc_name] = svc_info

    # If it's an access ticket — check if the submitter's account is locked
    if category == "access":
        username = state["employee_id"].lower().replace("-", ".")
        if username in SYSTEM_STATE["users"]:
            context["account"] = SYSTEM_STATE["users"][username]

    # If it's a hardware ticket — check disk states
    if category == "hardware":
        context["disk"] = {}
        for drive, info in SYSTEM_STATE["disk"].items():
            pct = info["used_gb"] / info["total_gb"]
            if pct >= 0.80:  # only report drives that are problematic
                context["disk"][drive] = info

    state["system_context"] = context
    return state


def run_pipeline(raw_input: str, submitter: str, employee_id: str) -> dict:
    """
    Executes the full 5-agent ARIA pipeline for a single ticket submission.

    Each agent receives the shared state dict, modifies its designated
    section, and returns the updated state. State is never duplicated —
    the same object is passed through every stage.

    The pipeline terminates early if the Security agent blocks the input.
    All other agents run unconditionally in sequence. The Escalation agent
    is conditional — it only fires if the Resolution agent could not
    auto-resolve the ticket.

    Args:
        raw_input:   Raw ticket description as entered by the user
        submitter:   Full name of the submitting employee
        employee_id: Employee ID string

    Returns:
        Final state dict with all agent output sections populated.
        Check state["status"] to determine the outcome:
          "auto_resolved" → tool executed successfully
          "escalated"     → routed to human agent
          "failed"        → tool executed but reported failure
          "blocked"       → security check failed, pipeline terminated
    """

    # Initialise a fresh, isolated state object for this ticket.
    # Every submission gets its own independent state — no shared memory
    # between concurrent tickets.
    state = build_initial_state(raw_input, submitter, employee_id)

    # ── Phase 1: Security (runs first, can terminate pipeline) ────────────
    # Pure Python guardrails — no LLM involved.
    # If security check fails (injection, invalid length), pipeline stops
    # here and returns immediately. No agent or LLM ever sees the input.
    state = security_agent(state)
    if not state["security"]["passed"]:
        return state

    # ── Phase 2: Intake ───────────────────────────────────────────────────
    # Classifies the ticket: severity, category, urgency reason, summary.
    # Uses masked_input (PII-scrubbed) rather than raw_input.
    state = intake_agent(state)

    # ── Phase 3: Diagnosis ────────────────────────────────────────────────
    # Determines root cause, affected system, and confidence score.
    # The confidence score produced here gates Phase 4's auto-execution.
    state = diagnosis_agent(state)

    # ── Phase 4: Resolution ───────────────────────────────────────────────
    # Selects and executes the appropriate tool from AVAILABLE_TOOLS.
    # Three-gate safety check inside resolution_agent():
    #   Gate 1 — LLM assessed as auto-fixable
    #   Gate 2 — confidence >= CONFIDENCE_THRESHOLD
    #   Gate 3 — tool name is in the whitelist
    # Any gate failure sets status to "escalated" without executing anything.
    state = resolution_agent(state)

    

    # ── Phase 5: Escalation (conditional) ────────────────────────────────
    # Only runs when resolution could not auto-fix the ticket.
    # Prepares a complete human handoff package with full diagnostic context.
    # This is the Human-in-the-Loop (HITL) trigger.
    if state["resolution"]["status"] in ("escalated", "failed"):
        state = escalation_agent(state)

    return state