"""
agents.py
─────────────────────────────────────────────────────────────────────────────
ARIA — Automated Resolution & Incident Agent
Agent definitions for the 5-agent IT service desk pipeline.

Each agent follows a strict contract:
  - Receives the shared state dictionary
  - Reads only from its designated input fields
  - Writes only to its designated output section
  - Appends exactly one entry to the audit log
  - Returns the updated state dictionary

Agents never communicate with each other directly.
All inter-agent communication flows through the shared state object.

LLM assignments (fit-for-purpose model selection):
  Security   → No LLM. Pure Python guardrails only.
  Intake     → Groq / Llama 3.3 70B    (fast, low-latency classification)
  Diagnosis  → Gemini 2.0 Flash         (strongest free reasoning model)
  Resolution → Cerebras / Llama 3.3 70B (high daily token volume)
  Escalation → OpenRouter / Mistral 7B  (model variety for judgment calls)

Each agent has its own fallback LLM — agent-local, not system-wide.
If the primary provider hits a rate limit, the fallback fires automatically.
─────────────────────────────────────────────────────────────────────────────
"""

import os
import json
import re

from openai import OpenAI
from dotenv import load_dotenv

from guardrails import run_security_checks, filter_output
from tools import AVAILABLE_TOOLS
from state import append_audit

# Load environment variables from .env file
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))
try:
    import streamlit as st
    for key in ["GROQ_API_KEY", "GEMINI_API_KEY",
                "CEREBRAS_API_KEY", "OPENROUTER_API_KEY",
                "CONFIDENCE_THRESHOLD", "COMPANY_DOMAIN"]:
        if key in st.secrets:
            os.environ[key] = st.secrets[key]
except Exception:
    pass

# ═════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# All tuneable values live here. Change behaviour by editing .env or this
# block — never by touching agent logic further down the file.
# ═════════════════════════════════════════════════════════════════════════════

# Confidence gate: Resolution agent will not auto-execute a tool unless its
# confidence score meets or exceeds this threshold. Below it → escalate.
# Tunable via .env so demo scenarios can be adjusted without code changes.
CONFIDENCE_THRESHOLD = float(os.getenv("CONFIDENCE_THRESHOLD", "0.75"))

# Model registry: maps each agent role to its primary and fallback model.
# Changing a model requires editing this block only — agent functions are
# fully decoupled from model names.
MODELS = {
    # Groq — Llama 3.3 70B: fast, reliable, excellent JSON output
    "intake_primary":      os.getenv("MODEL_INTAKE_PRIMARY",      "llama-3.3-70b-versatile"),
    "intake_fallback":     os.getenv("MODEL_INTAKE_FALLBACK",      "llama-3.1-8b-instant"),

    # Gemini 2.5 Flash: strongest free reasoning model available
    "diagnosis_primary":   os.getenv("MODEL_DIAGNOSIS_PRIMARY",    "models/gemini-2.5-flash"),
    "diagnosis_fallback":  os.getenv("MODEL_DIAGNOSIS_FALLBACK",   "llama-3.3-70b-versatile"),

    # Groq — Llama 3.3 70B: most consistent JSON output for tool chain
    "resolution_primary":  os.getenv("MODEL_RESOLUTION_PRIMARY",   "llama-3.3-70b-versatile"),
    "resolution_fallback": os.getenv("MODEL_RESOLUTION_FALLBACK",  "llama-3.1-8b-instant"),

    # Qwen3 32B on Groq: replaces Mistral for judgment/escalation calls
    "escalation_primary":  os.getenv("MODEL_ESCALATION_PRIMARY",   "llama-3.3-70b-versatile"),
    "escalation_fallback": os.getenv("MODEL_ESCALATION_FALLBACK",  "llama-3.3-70b-versatile"),
}


# ═════════════════════════════════════════════════════════════════════════════
# LLM CLIENTS
# One client per provider. Each client is scoped to one agent.
# All providers use the OpenAI-compatible API format, so the same
# .chat.completions.create() call works for every client.
# API keys are read exclusively from environment variables — never hardcoded.
# ═════════════════════════════════════════════════════════════════════════════

# Groq — ultra-low latency, free tier, used for Intake agent (primary)
# and as fallback for Diagnosis and Escalation agents
groq_client = OpenAI(
    api_key=os.getenv("GROQ_API_KEY"),
    base_url="https://api.groq.com/openai/v1",
)

# Google AI Studio — strongest free reasoning model, used for Diagnosis (primary)
# and as fallback for Intake agent
gemini_client = OpenAI(
    api_key=os.getenv("GEMINI_API_KEY"),
    base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
)

# Cerebras — highest free daily token volume, used for Resolution agent (primary)
# Resolution generates the most tokens due to tool selection reasoning
cerebras_client = OpenAI(
    api_key=os.getenv("CEREBRAS_API_KEY"),
    base_url="https://api.cerebras.ai/v1",
)

# OpenRouter — aggregates 20+ free models, used for Escalation agent (primary)
# Variety of models reduces monoculture bias in judgment calls
openrouter_client = OpenAI(
    api_key=os.getenv("OPENROUTER_API_KEY"),
    base_url="https://openrouter.ai/api/v1",
)


# ═════════════════════════════════════════════════════════════════════════════
# SHARED UTILITIES
# Helper functions used by all agents. Not agent-specific.
# ═════════════════════════════════════════════════════════════════════════════

def load_prompt(agent_name: str) -> str:
    """
    Loads a system prompt from the prompts/ directory.

    Prompts are stored as plain text files — separate from Python logic.
    This means prompt engineering can happen without touching agent code,
    which mirrors production prompt management practices.

    Args:
        agent_name: Name of the agent (e.g. "intake", "diagnosis")

    Returns:
        The prompt string loaded from prompts/{agent_name}_prompt.txt

    Raises:
        FileNotFoundError: If the prompt file does not exist
    """
    path = os.path.join("prompts", f"{agent_name}_prompt.txt")
    with open(path, "r") as f:
        return f.read().strip()


def safe_parse_json(text: str) -> dict | None:
    """
    Safely extracts and parses a JSON object from an LLM response string.

    LLMs occasionally wrap JSON in markdown code fences (```json ... ```)
    or prefix it with explanatory text. This function handles both cases
    by first attempting a direct parse, then falling back to regex extraction.

    Args:
        text: Raw string response from the LLM

    Returns:
        Parsed dictionary if successful, None if parsing fails entirely.
        Callers must handle the None case with a safe default.
    """
    if not text:
        return None

    # Attempt 1: direct parse (works when LLM follows instructions correctly)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Attempt 2: extract JSON object using regex, ignoring surrounding text
    try:
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            return json.loads(match.group())
    except (json.JSONDecodeError, AttributeError):
        pass

    # Both attempts failed — caller will use safe defaults
    return None


def call_llm(
    primary_client: OpenAI,
    primary_model: str,
    fallback_client: OpenAI,
    fallback_model: str,
    system_prompt: str,
    user_message: str,
    max_tokens: int = 500,
) -> str:
    """
    Calls the primary LLM and automatically falls back to secondary on failure.

    Failure conditions that trigger fallback:
      - Rate limit exceeded (HTTP 429)
      - Provider timeout or network error
      - Any other exception from the primary provider

    Temperature is set to 0.1 (near-deterministic) to maximise consistency
    of JSON output format. Higher temperature increases hallucination risk
    in structured output tasks.

    Args:
        primary_client:  OpenAI-compatible client for primary provider
        primary_model:   Model string for primary provider
        fallback_client: OpenAI-compatible client for fallback provider
        fallback_model:  Model string for fallback provider
        system_prompt:   System-level instruction for the LLM
        user_message:    User-level input (the ticket content)
        max_tokens:      Hard cap on response length (cost + safety control)

    Returns:
        Raw string response from whichever LLM succeeded

    Raises:
        RuntimeError: If both primary and fallback providers fail
    """
    try:
        response = primary_client.chat.completions.create(
            model=primary_model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_message},
            ],
            max_tokens=max_tokens,
            temperature=0.1,
        )
        return response.choices[0].message.content

    except Exception as primary_error:
        # Log the primary failure for observability, then try fallback
        print(f"[FALLBACK] Primary LLM ({primary_model}) failed: {primary_error}")
        try:
            response = fallback_client.chat.completions.create(
                model=fallback_model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_message},
                ],
                max_tokens=max_tokens,
                temperature=0.1,
            )
            return response.choices[0].message.content

        except Exception as fallback_error:
            raise RuntimeError(
                f"Both LLMs failed.\n"
                f"  Primary  ({primary_model}): {primary_error}\n"
                f"  Fallback ({fallback_model}): {fallback_error}"
            )


# ═════════════════════════════════════════════════════════════════════════════
# AGENT 1 — SECURITY AGENT
# ─────────────────────────────────────────────────────────────────────────────
# Layer:      1 — Guardrail (runs before all other agents)
# LLM:        None — pure Python logic only
# Writes to:  state["security"], state["masked_input"], state["status"]
# Can block:  Yes — sets status="blocked" and returns early
#
# Design rationale: An LLM should never be the guard for LLM-based attacks.
# Using an LLM to detect prompt injection creates a circular vulnerability.
# Pure deterministic Python is the only appropriate security layer here.
# ═════════════════════════════════════════════════════════════════════════════

def security_agent(state: dict) -> dict:
    """
    Runs all input guardrails before any agent or LLM sees the ticket.

    Three sequential checks:
      1. Length validation   — rejects inputs outside 10–2000 char bounds
      2. Injection detection — blocks known prompt hijacking patterns
      3. PII masking         — redacts emails, phone numbers, SSNs, card numbers

    If any check fails, the pipeline is terminated immediately.
    The blocked state is recorded in the audit log for compliance tracing.

    Args:
        state: Shared state dict with raw_input populated

    Returns:
        Updated state with security section populated.
        If blocked, status="blocked" and pipeline should not continue.
    """
    result = run_security_checks(state["raw_input"])

    # Write results to the security section of shared state
    state["masked_input"]                       = result["masked_text"]
    state["security"]["passed"]                 = result["passed"]
    state["security"]["injection_detected"]     = result["injection_detected"]
    state["security"]["pii_items_masked"]       = result["pii_items_masked"]
    state["security"]["block_reason"]           = result["block_reason"]

    if result["passed"]:
        state["status"] = "secured"
        append_audit(
            state,
            event="security_passed",
            detail=f"PII masked: {result['pii_items_masked']} items",
        )
    else:
        state["status"] = "blocked"
        append_audit(
            state,
            event="security_blocked",
            detail=result["block_reason"],
        )

    return state


# ═════════════════════════════════════════════════════════════════════════════
# AGENT 2 — INTAKE AGENT
# ─────────────────────────────────────────────────────────────────────────────
# Layer:      2 — Processing
# LLM:        Groq / Llama 3.3 70B (primary) | Gemini 2.0 Flash (fallback)
# Reads from: state["masked_input"]
# Writes to:  state["intake"], state["status"]
#
# Design rationale: Classification is a fast, deterministic task.
# Groq's sub-second latency is optimal here. No dropdown is presented to
# the user — the agent infers severity from natural language context clues
# (time pressure, number of affected users, business impact language).
# This produces more accurate and more explainable classifications than
# user self-reporting, which is chronically unreliable in real service desks.
# ═════════════════════════════════════════════════════════════════════════════

def intake_agent(state: dict) -> dict:
    """
    Classifies the incoming ticket into structured fields.

    Outputs:
      severity:       low | medium | high | critical
      category:       access | network | hardware | software | other
      urgency_reason: one sentence explaining the severity decision
      summary:        clean one-line summary of the issue

    Safe defaults are applied if JSON parsing fails, ensuring the pipeline
    always continues rather than crashing on a bad LLM response.

    Args:
        state: Shared state with masked_input populated by Security agent

    Returns:
        Updated state with intake section populated
    """
    system_prompt = load_prompt("intake")
    user_message  = (
        f"Classify this IT support ticket:\n\n{state['masked_input']}"
    )

    raw = call_llm(
        primary_client=groq_client,
        primary_model=MODELS["intake_primary"],
        fallback_client=groq_client,
        fallback_model=MODELS["intake_fallback"],
        system_prompt=system_prompt,
        user_message=user_message,
        max_tokens=300,
    )

    result = safe_parse_json(raw)

    if result:
        state["intake"]["severity"]       = result.get("severity",       "medium")
        state["intake"]["category"]       = result.get("category",       "other")
        state["intake"]["urgency_reason"] = result.get("urgency_reason", "Could not determine urgency")
        state["intake"]["summary"]        = result.get("summary",        state["masked_input"][:120])
        state["status"] = "triaged"
        append_audit(
            state,
            event="intake_complete",
            detail=f"{state['intake']['severity']} · {state['intake']['category']}",
        )
    else:
        # Safe fallback: pipeline continues with conservative defaults
        state["intake"] = {
            "severity":       "medium",
            "category":       "other",
            "urgency_reason": "Classification failed — defaulting to medium",
            "summary":        state["masked_input"][:120],
        }
        state["status"] = "triaged"
        append_audit(state, event="intake_fallback", detail="JSON parse failed — defaults applied")

    return state


# ═════════════════════════════════════════════════════════════════════════════
# AGENT 3 — DIAGNOSIS AGENT
# ─────────────────────────────────────────────────────────────────────────────
# Layer:      2 — Processing
# LLM:        Gemini 2.0 Flash (primary) | Groq / Llama 3.3 70B (fallback)
# Reads from: state["masked_input"], state["intake"]
# Writes to:  state["diagnosis"], state["status"]
#
# Design rationale: Root cause analysis requires multi-step reasoning over
# ambiguous natural language. Gemini 2.0 Flash is the highest-quality free
# model available for this task. The confidence score produced here is the
# single most important value in the pipeline — it gates the Resolution
# agent's auto-execution decision.
# ═════════════════════════════════════════════════════════════════════════════

def diagnosis_agent(state: dict) -> dict:
    """
    Determines the technical root cause of the ticket.

    Outputs:
      root_cause:      specific technical reason for the issue
      affected_system: exact system, service, or username involved
      confidence:      float 0.0–1.0 representing diagnostic certainty
      reasoning:       explanation of how the diagnosis was reached

    The confidence score directly controls whether auto-remediation fires.
    Below CONFIDENCE_THRESHOLD → escalate to human regardless of tool availability.

    Args:
        state: Shared state with intake section populated

    Returns:
        Updated state with diagnosis section populated
    """
    system_prompt = load_prompt("diagnosis")
    user_message  = (
        f"Ticket summary:  {state['intake']['summary']}\n"
        f"Category:        {state['intake']['category']}\n"
        f"Severity:        {state['intake']['severity']}\n"
        f"Full description: {state['masked_input']}\n\n"
        f"Diagnose the root cause."
    )

    raw = call_llm(
        primary_client=gemini_client,
        primary_model=MODELS["diagnosis_primary"],
        fallback_client=groq_client,
        fallback_model=MODELS["diagnosis_fallback"],
        system_prompt=system_prompt,
        user_message=user_message,
        max_tokens=400,
    )

    result = safe_parse_json(raw)

    if result:
        state["diagnosis"]["root_cause"]      = result.get("root_cause",      "Could not determine root cause")
        state["diagnosis"]["affected_system"] = result.get("affected_system", "unknown")
        state["diagnosis"]["confidence"]      = float(result.get("confidence", 0.5))
        state["diagnosis"]["reasoning"]       = result.get("reasoning",       "")
        state["status"] = "diagnosed"
        append_audit(
            state,
            event="diagnosis_complete",
            detail=f"confidence: {state['diagnosis']['confidence']}",
        )
    else:
        # Conservative fallback: low confidence forces escalation downstream
        state["diagnosis"] = {
            "root_cause":      "Could not diagnose — insufficient information",
            "affected_system": "unknown",
            "confidence":      0.4,
            "reasoning":       "JSON parse failed — conservative confidence assigned",
        }
        state["status"] = "diagnosed"
        append_audit(state, event="diagnosis_fallback", detail="JSON parse failed — confidence set to 0.4")

    return state


# ═════════════════════════════════════════════════════════════════════════════
# AGENT 4 — RESOLUTION AGENT
# ─────────────────────────────────────────────────────────────────────────────
# Layer:      2 — Processing
# LLM:        Cerebras / Llama 3.3 70B (primary) | Groq (fallback)
# Reads from: state["intake"], state["diagnosis"]
# Writes to:  state["resolution"], state["status"]
#
# Design rationale: Resolution generates the most tokens (tool reasoning +
# argument construction). Cerebras provides the highest free daily volume.
#
# Tool chain design:
#   A single ticket may require multiple sequential tool executions.
#   Example: account locked + password expired requires:
#     1. unlock_account  → restores login access
#     2. send_password_reset → handles the expiry
#   The LLM returns an ordered tool_chain list (max 3 steps).
#   Python executes each step in order. If any step fails, the chain
#   stops immediately and the ticket escalates — partial execution is
#   never silently completed. This is transactional behaviour.
#
# Critical security design: The LLM selects WHICH tools to use and with WHAT
# arguments, but Python executes them. The LLM never has direct system access.
# Three gates must all pass before ANY tool in the chain executes:
#   Gate 1 — can_auto_fix must be True (LLM self-assessed)
#   Gate 2 — confidence must meet CONFIDENCE_THRESHOLD (0.75 default)
#   Gate 3 — every tool name in the chain must exist in AVAILABLE_TOOLS
# Any gate failure → immediate escalation, no execution.
# ═════════════════════════════════════════════════════════════════════════════

def resolution_agent(state: dict) -> dict:
    """
    Selects and executes an ordered chain of remediation tools.

    The LLM returns a structured JSON decision containing a tool_chain —
    an ordered list of tools to execute. Python validates the full chain
    before executing any step, then runs each tool in sequence.

    Execution is transactional: if any tool in the chain fails, execution
    stops immediately. The ticket escalates with a full record of which
    steps succeeded and which failed. No partial state is silently accepted.

    Three-gate execution model (all must pass before chain runs):
      Gate 1: can_auto_fix == True
      Gate 2: confidence >= CONFIDENCE_THRESHOLD
      Gate 3: every tool name in chain exists in AVAILABLE_TOOLS whitelist

    Outputs written to state["resolution"]:
      can_auto_fix:  LLM self-assessment of whether auto-execution is safe
      tool_chain:    ordered list of [{tool, arguments}] dicts (max 3)
      confidence:    LLM confidence in the full chain (0.0–1.0)
      explanation:   why each tool was selected and in what order
      tool_results:  list of result dicts — one per executed tool
      status:        auto_resolved | escalated | failed

    Args:
        state: Shared state with intake and diagnosis sections populated

    Returns:
        Updated state with resolution section populated
    """
    system_prompt = load_prompt("resolution")
    user_message  = (
        f"Root cause:           {state['diagnosis']['root_cause']}\n"
        f"Affected system:      {state['diagnosis']['affected_system']}\n"
        f"Diagnosis confidence: {state['diagnosis']['confidence']}\n"
        f"Category:             {state['intake']['category']}\n"
        f"Ticket summary:       {state['intake']['summary']}\n\n"
        f"Select the tool or tools needed to fully resolve this issue."
    )

    raw = call_llm(
        primary_client=groq_client,
        primary_model=MODELS["resolution_primary"],
        fallback_client=groq_client,
        fallback_model=MODELS["resolution_fallback"],
        system_prompt=system_prompt,
        user_message=user_message,
        max_tokens=600,  # increased to accommodate multi-tool chain JSON
    )

    result = safe_parse_json(raw)

    # If JSON parsing failed entirely, skip to escalation
    if not result:
        state["resolution"]["status"]      = "escalated"
        state["resolution"]["explanation"] = "Could not parse resolution decision — escalating"
        state["status"] = "escalated"
        append_audit(state, event="resolution_parse_failed", detail="escalating to human")
        return state

    # ── Populate resolution fields from LLM decision ──────────────────────
    can_fix    = result.get("can_auto_fix", False)
    tool_chain = result.get("tool_chain", [])
    confidence = float(result.get("confidence", 0.0))
    explanation = result.get("explanation", "")

    state["resolution"]["can_auto_fix"] = can_fix
    state["resolution"]["tool_chain"]   = tool_chain
    state["resolution"]["confidence"]   = confidence
    state["resolution"]["explanation"]  = explanation
    state["resolution"]["tool_results"] = []

    # ── Gate 1: LLM self-assessed viability ──────────────────────────────
    if not can_fix:
        state["resolution"]["status"] = "escalated"
        state["status"]               = "escalated"
        append_audit(
            state,
            event="resolution_escalated",
            detail="agent assessed as not auto-fixable",
        )
        return state

    # ── Gate 2: Confidence threshold ─────────────────────────────────────
    if confidence < CONFIDENCE_THRESHOLD:
        state["resolution"]["status"] = "escalated"
        state["status"]               = "escalated"
        append_audit(
            state,
            event="resolution_escalated",
            detail=f"confidence {confidence:.2f} below threshold {CONFIDENCE_THRESHOLD}",
        )
        return state

    # ── Gate 3: Whitelist check — validate entire chain before running any step
    # This prevents partial execution where some tools run before an invalid
    # tool name is discovered mid-chain.
    invalid_tools = [
        step.get("tool") for step in tool_chain
        if step.get("tool") not in AVAILABLE_TOOLS
    ]
    if invalid_tools:
        state["resolution"]["status"] = "escalated"
        state["status"]               = "escalated"
        append_audit(
            state,
            event="resolution_escalated",
            detail=f"tool(s) not in whitelist: {invalid_tools}",
        )
        return state

    # ── All gates passed — execute the tool chain ─────────────────────────
    # Tools run in order. If any tool fails, stop immediately and escalate.
    # This is transactional behaviour — no partial success is silently accepted.
    chain_succeeded = True

    for step_index, step in enumerate(tool_chain):
        tool_name = step.get("tool")
        args      = step.get("arguments", {})
        tool_fn   = AVAILABLE_TOOLS[tool_name]

        try:
            tool_result = tool_fn(**args)

            # Record result with all available fields for rich UI display
            state["resolution"]["tool_results"].append({
                "step":                  step_index + 1,
                "tool":                  tool_name,
                "args":                  args,
                "success":               tool_result.get("success"),
                "message":               tool_result.get("message", ""),
                "reason":                tool_result.get("reason", ""),
                # Service fields — populated by get_service_status and restart_service
                "status":                tool_result.get("status"),
                "affected_users":        tool_result.get("affected_users"),
                "previous_status":       tool_result.get("previous_status"),
                "current_status":        tool_result.get("current_status"),
                # Disk fields — populated by clear_disk_space and free_up_disk_aggressive
                "freed_gb":              tool_result.get("freed_gb"),
                "was_used_gb":           tool_result.get("was_used_gb"),
                "now_used_gb":           tool_result.get("now_used_gb"),
                # Account fields — populated by check_account_status
                "locked":                tool_result.get("locked"),
                "password_expires_days": tool_result.get("password_expires_days"),
            })

            append_audit(
                state,
                event=f"tool_executed · step {step_index + 1} · {tool_name}",
                detail=f"success: {tool_result.get('success')} — {tool_result.get('message', tool_result.get('reason', ''))}",
            )

            if not tool_result.get("success"):
                # Tool reported failure — stop chain immediately
                chain_succeeded = False
                append_audit(
                    state,
                    event="chain_stopped",
                    detail=f"step {step_index + 1} failed — remaining steps cancelled",
                )
                break

            # ── Inter-step result validation ───────────────────────────────
            # Read-only check tools (get_service_status, check_account_status)
            # run first in the chain. If the system is already in the desired
            # state, stop early — don't run destructive steps unnecessarily.

            if tool_name == "get_service_status":
                service_status = tool_result.get("status", "unknown")
                if service_status == "running":
                    # Service is already running — no restart needed
                    state["resolution"]["explanation"] = (
                        f"Service '{args.get('service_name')}' is confirmed running "
                        f"with {tool_result.get('affected_users', 0)} users affected. "
                        f"No restart needed — issue may be client-side."
                    )
                    state["resolution"]["status"] = "auto_resolved"
                    state["status"]               = "auto_resolved"
                    append_audit(
                        state,
                        event="chain_stopped_early",
                        detail="service already running — restart skipped",
                    )
                    chain_succeeded = True
                    break

            if tool_name == "check_account_status":
                if not tool_result.get("locked"):
                    # Account is already active — no unlock needed
                    state["resolution"]["explanation"] = (
                        f"Account '{args.get('username')}' is confirmed active. "
                        f"No unlock needed."
                    )
                    state["resolution"]["status"] = "auto_resolved"
                    state["status"]               = "auto_resolved"
                    append_audit(
                        state,
                        event="chain_stopped_early",
                        detail="account already active — unlock skipped",
                    )
                    chain_succeeded = True
                    break

        except Exception as execution_error:
            # Unexpected exception — stop chain immediately
            state["resolution"]["tool_results"].append({
                "step":    step_index + 1,
                "tool":    tool_name,
                "args":    args,
                "success": False,
                "message": "",
                "reason":  str(execution_error),
            })
            chain_succeeded = False
            append_audit(
                state,
                event="tool_execution_error",
                detail=f"step {step_index + 1} · {tool_name} — {str(execution_error)}",
            )
            break

    # ── Set final resolution status based on chain outcome ────────────────
    if chain_succeeded:
        # Only set if not already set by early-stop validation above
        if state["resolution"]["status"] != "auto_resolved":
            state["resolution"]["status"] = "auto_resolved"
            state["status"]               = "auto_resolved"
            append_audit(
                state,
                event="chain_complete",
                detail=f"{len(tool_chain)} tool(s) executed successfully",
            )
    else:
        state["resolution"]["status"] = "failed"
        state["status"]               = "failed"
        failed_steps = [
            r for r in (state["resolution"]["tool_results"] or [])
            if not r.get("success")
        ]
        chain_fail_reason = (
            f"step {failed_steps[0]['step']} · {failed_steps[0]['tool']} failed"
            if failed_steps else "tool chain failed"
        )
        append_audit(
            state,
            event="resolution_failed",
            detail=chain_fail_reason,
        )

    return state


# ═════════════════════════════════════════════════════════════════════════════
# AGENT 5 — ESCALATION AGENT
# ─────────────────────────────────────────────────────────────────────────────
# Layer:      3 — Decision (conditional — only runs when resolution fails)
# LLM:        OpenRouter / Mistral 7B (primary) | Groq (fallback)
# Reads from: state["intake"], state["diagnosis"], state["resolution"]
# Writes to:  state["escalation"], state["status"]
#
# Design rationale: Escalation is a judgment call — which team, what priority,
# how to frame the handoff. OpenRouter's model variety reduces monoculture
# bias in these nuanced decisions. The key value this agent provides is NOT
# routing — it's the pre-populated context package. A human agent receiving
# a ticket with full diagnostic context starts informed rather than from zero.
# This is the core Human-in-the-Loop (HITL) value proposition.
# ═════════════════════════════════════════════════════════════════════════════

def escalation_agent(state: dict) -> dict:
    """
    Prepares a complete handoff package for the human IT agent.

    Only fires when Resolution status is "escalated" or "failed".
    The goal is not just to route the ticket — it is to ensure the
    receiving human agent has everything they need to resolve it
    efficiently without re-investigating from scratch.

    Outputs:
      team:     which team to route to (IT Support / Network / Hardware / Security)
      priority: escalated priority level
      summary:  two-sentence human-readable summary
      context:  full diagnostic context for the receiving agent

    Args:
        state: Shared state with all prior agent sections populated

    Returns:
        Updated state with escalation section populated and status="escalated"
    """
    system_prompt = load_prompt("escalation")
    user_message  = (
        f"Ticket:                {state['intake']['summary']}\n"
        f"Severity:              {state['intake']['severity']}\n"
        f"Category:              {state['intake']['category']}\n"
        f"Root cause:            {state['diagnosis']['root_cause']}\n"
        f"Diagnosis confidence:  {state['diagnosis']['confidence']}\n"
        f"Resolution attempted:  {state['resolution']['tool_chain']}\n"
        f"Resolution outcome:    {state['resolution']['status']}\n"
        f"Resolution reasoning:  {state['resolution']['explanation']}\n\n"
        f"Prepare the human handoff package."
    )

    raw = call_llm(
        primary_client=groq_client,
        primary_model=MODELS["escalation_primary"],
        fallback_client=groq_client,
        fallback_model=MODELS["escalation_fallback"],
        system_prompt=system_prompt,
        user_message=user_message,
        max_tokens=500,
    )

    result = safe_parse_json(raw)

    if result:
        state["escalation"]["team"]     = result.get("team",     "IT Support")
        state["escalation"]["priority"] = result.get("priority", state["intake"]["severity"])
        state["escalation"]["summary"]  = result.get("summary",  state["intake"]["summary"])
        state["escalation"]["context"]  = result.get("context",  "No additional context available")
        append_audit(
            state,
            event="escalated_to_human",
            detail=f"team: {state['escalation']['team']} · priority: {state['escalation']['priority']}",
        )
    else:
        # Conservative fallback: route to IT Support with available information
        state["escalation"] = {
            "team":     "IT Support",
            "priority": state["intake"]["severity"],
            "summary":  state["intake"]["summary"],
            "context":  (
                f"Auto-escalated. Root cause: {state['diagnosis']['root_cause']}. "
                f"Confidence: {state['diagnosis']['confidence']}."
            ),
        }
        append_audit(state, event="escalation_fallback", detail="JSON parse failed — conservative defaults applied")

    state["status"] = "escalated"
    return state