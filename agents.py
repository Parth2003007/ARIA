"""
agents.py
─────────────────────────────────────────────────────────────────────────────
ARIA — Automated Resolution & Incident Agent
Agent definitions for the 5-agent IT service desk pipeline.
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
from mock_system import SYSTEM_STATE

# Load environment variables from .env file (local development)
load_dotenv()

# Streamlit Cloud: load secrets into os.environ
# This runs at import time before get_clients() is called
try:
    import streamlit as st
    for _key in ["GROQ_API_KEY", "GEMINI_API_KEY",
                 "CEREBRAS_API_KEY", "OPENROUTER_API_KEY",
                 "CONFIDENCE_THRESHOLD", "COMPANY_DOMAIN"]:
        if _key in st.secrets:
            os.environ[_key] = str(st.secrets[_key])
except Exception:
    pass

# Confidence gate threshold
CONFIDENCE_THRESHOLD = float(os.getenv("CONFIDENCE_THRESHOLD", "0.75"))

# Model registry
MODELS = {
    "intake_primary":      os.getenv("MODEL_INTAKE_PRIMARY",     "llama-3.3-70b-versatile"),
    "intake_fallback":     os.getenv("MODEL_INTAKE_FALLBACK",    "llama-3.3-70b-versatile"),
    "diagnosis_primary":   os.getenv("MODEL_DIAGNOSIS_PRIMARY",  "models/gemini-2.5-flash"),
    "diagnosis_fallback":  os.getenv("MODEL_DIAGNOSIS_FALLBACK", "llama-3.3-70b-versatile"),
    "resolution_primary":  os.getenv("MODEL_RESOLUTION_PRIMARY", "llama-3.3-70b-versatile"),
    "resolution_fallback": os.getenv("MODEL_RESOLUTION_FALLBACK","llama-3.3-70b-versatile"),
    "escalation_primary":  os.getenv("MODEL_ESCALATION_PRIMARY", "llama-3.3-70b-versatile"),
    "escalation_fallback": os.getenv("MODEL_ESCALATION_FALLBACK","llama-3.3-70b-versatile"),
}


# ═════════════════════════════════════════════════════════════════════════════
# LAZY CLIENT FACTORY
# Clients are created on first use — not at module import time.
# This prevents OpenAI from raising "Missing credentials" during import
# on Streamlit Cloud before secrets have been injected into os.environ.
# ═════════════════════════════════════════════════════════════════════════════

_clients = {}

EMPLOYEE_USERNAME_MAP = {
    "EMP-4821": "john.doe",
    "EMP-1032": "jane.smith",
    "EMP-2201": "bob.jones",
    "EMP-3341": "sara.chen",
}

ACCOUNT_TOOLS = {
    "check_account_status",
    "unlock_account",
    "send_password_reset",
    "extend_password_expiry",
    "install_software",
}

PLACEHOLDER_USERNAMES = {
    "",
    "user",
    "username",
    "user_username",
    "user's_username",
    "user.name",
    "unknown",
}

def get_client(name: str) -> OpenAI:
    """
    Returns a cached OpenAI-compatible client for the given provider name.
    Created on first call — not at module import time.
    """
    if name not in _clients:
        if name == "groq":
            _clients[name] = OpenAI(
                api_key=os.getenv("GROQ_API_KEY"),
                base_url="https://api.groq.com/openai/v1",
            )
        elif name == "gemini":
            _clients[name] = OpenAI(
                api_key=os.getenv("GEMINI_API_KEY"),
                base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
            )
        elif name == "cerebras":
            _clients[name] = OpenAI(
                api_key=os.getenv("CEREBRAS_API_KEY"),
                base_url="https://api.cerebras.ai/v1",
            )
        elif name == "openrouter":
            _clients[name] = OpenAI(
                api_key=os.getenv("OPENROUTER_API_KEY"),
                base_url="https://openrouter.ai/api/v1",
            )
    return _clients[name]


# ═════════════════════════════════════════════════════════════════════════════
# SHARED UTILITIES
# ═════════════════════════════════════════════════════════════════════════════

def load_prompt(agent_name: str) -> str:
    path = os.path.join("prompts", f"{agent_name}_prompt.txt")
    with open(path, "r") as f:
        return f.read().strip()


def safe_parse_json(text: str) -> dict | None:
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    try:
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            return json.loads(match.group())
    except (json.JSONDecodeError, AttributeError):
        pass
    return None


def submitter_to_username(submitter: str) -> str | None:
    """
    Converts a display name such as "John Doe" into the demo username
    convention "john.doe", returning None if it is not a known user.
    """
    candidate = ".".join(submitter.lower().strip().split())
    return candidate if candidate in SYSTEM_STATE["users"] else None


def resolve_account_username(state: dict) -> str | None:
    """
    Resolves the account username from deterministic ticket context.
    Preference order:
      1. Explicit known username in the original or masked ticket text
      2. Exact affected_system match from Diagnosis
      3. Employee ID directory mapping
      4. Submitter display-name convention
    """
    known_users = set(SYSTEM_STATE["users"])
    text_sources = [
        state.get("raw_input") or "",
        state.get("masked_input") or "",
        state.get("diagnosis", {}).get("affected_system") or "",
    ]

    for text in text_sources:
        lowered = text.lower()
        for username in known_users:
            if username in lowered:
                return username

    employee_id = state.get("employee_id") or ""
    mapped_username = EMPLOYEE_USERNAME_MAP.get(employee_id)
    if mapped_username in known_users:
        return mapped_username

    return submitter_to_username(state.get("submitter") or "")


def username_needs_resolution(username: object) -> bool:
    """Returns True when an LLM-supplied username is missing or placeholder-like."""
    if not isinstance(username, str):
        return True

    normalized = username.strip().lower()
    if normalized in SYSTEM_STATE["users"]:
        return False
    if normalized in PLACEHOLDER_USERNAMES:
        return True

    return "user" in normalized and "username" in normalized


def normalize_tool_chain_arguments(state: dict, tool_chain: list[dict]) -> list[dict]:
    """
    Replaces placeholder account usernames with the submitter's verified demo
    account before tool execution. The LLM still selects the tool chain; Python
    resolves identity from trusted ticket metadata.
    """
    resolved_username = resolve_account_username(state)
    if not resolved_username:
        return tool_chain

    normalized_chain = []
    replacements = []

    for step in tool_chain:
        updated_step = dict(step)
        args = dict(updated_step.get("arguments") or {})

        if updated_step.get("tool") in ACCOUNT_TOOLS and username_needs_resolution(args.get("username")):
            previous = args.get("username", "")
            args["username"] = resolved_username
            updated_step["arguments"] = args
            replacements.append(f"{updated_step.get('tool')}: {previous!r} -> {resolved_username!r}")

        normalized_chain.append(updated_step)

    if replacements:
        append_audit(state, event="tool_args_normalized", detail="; ".join(replacements))

    return normalized_chain


def call_llm(
    primary_name: str,
    primary_model: str,
    fallback_name: str,
    fallback_model: str,
    system_prompt: str,
    user_message: str,
    max_tokens: int = 500,
) -> str:
    """
    Calls the primary LLM by provider name and falls back on failure.
    Uses get_client() for lazy client instantiation.
    """
    primary_client  = get_client(primary_name)
    fallback_client = get_client(fallback_name)

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
# Layer 1 — Guardrail. No LLM. Pure Python only.
# ═════════════════════════════════════════════════════════════════════════════

def security_agent(state: dict) -> dict:
    result = run_security_checks(state["raw_input"])

    state["masked_input"]                   = result["masked_text"]
    state["security"]["passed"]             = result["passed"]
    state["security"]["injection_detected"] = result["injection_detected"]
    state["security"]["pii_items_masked"]   = result["pii_items_masked"]
    state["security"]["block_reason"]       = result["block_reason"]

    if result["passed"]:
        state["status"] = "secured"
        append_audit(state, event="security_passed",
                     detail=f"PII masked: {result['pii_items_masked']} items")
    else:
        state["status"] = "blocked"
        append_audit(state, event="security_blocked", detail=result["block_reason"])

    return state


# ═════════════════════════════════════════════════════════════════════════════
# AGENT 2 — INTAKE AGENT
# Layer 2. Groq / Llama 3.3 70B primary.
# ═════════════════════════════════════════════════════════════════════════════

def intake_agent(state: dict) -> dict:
    system_prompt = load_prompt("intake")
    user_message  = f"Classify this IT support ticket:\n\n{state['masked_input']}"

    raw = call_llm(
        primary_name="groq",   primary_model=MODELS["intake_primary"],
        fallback_name="groq",  fallback_model=MODELS["intake_fallback"],
        system_prompt=system_prompt, user_message=user_message, max_tokens=300,
    )

    result = safe_parse_json(raw)

    if result:
        state["intake"]["severity"]       = result.get("severity",       "medium")
        state["intake"]["category"]       = result.get("category",       "other")
        state["intake"]["urgency_reason"] = result.get("urgency_reason", "Could not determine urgency")
        state["intake"]["summary"]        = result.get("summary",        state["masked_input"][:120])
        state["status"] = "triaged"
        append_audit(state, event="intake_complete",
                     detail=f"{state['intake']['severity']} · {state['intake']['category']}")
    else:
        state["intake"] = {
            "severity": "medium", "category": "other",
            "urgency_reason": "Classification failed — defaulting to medium",
            "summary": state["masked_input"][:120],
        }
        state["status"] = "triaged"
        append_audit(state, event="intake_fallback", detail="JSON parse failed — defaults applied")

    return state


# ═════════════════════════════════════════════════════════════════════════════
# AGENT 3 — DIAGNOSIS AGENT
# Layer 2. Gemini 2.5 Flash primary.
# ═════════════════════════════════════════════════════════════════════════════

def diagnosis_agent(state: dict) -> dict:
    system_prompt = load_prompt("diagnosis")
    user_message  = (
        f"Ticket summary:  {state['intake']['summary']}\n"
        f"Category:        {state['intake']['category']}\n"
        f"Severity:        {state['intake']['severity']}\n"
        f"Full description: {state['masked_input']}\n\n"
        f"Diagnose the root cause."
    )

    raw = call_llm(
        primary_name="gemini",  primary_model=MODELS["diagnosis_primary"],
        fallback_name="groq",   fallback_model=MODELS["diagnosis_fallback"],
        system_prompt=system_prompt, user_message=user_message, max_tokens=400,
    )

    result = safe_parse_json(raw)

    if result:
        state["diagnosis"]["root_cause"]      = result.get("root_cause",      "Could not determine root cause")
        state["diagnosis"]["affected_system"] = result.get("affected_system", "unknown")
        state["diagnosis"]["confidence"]      = float(result.get("confidence", 0.5))
        state["diagnosis"]["reasoning"]       = result.get("reasoning",       "")
        state["status"] = "diagnosed"
        append_audit(state, event="diagnosis_complete",
                     detail=f"confidence: {state['diagnosis']['confidence']}")
    else:
        state["diagnosis"] = {
            "root_cause": "Could not diagnose — insufficient information",
            "affected_system": "unknown", "confidence": 0.4,
            "reasoning": "JSON parse failed — conservative confidence assigned",
        }
        state["status"] = "diagnosed"
        append_audit(state, event="diagnosis_fallback", detail="JSON parse failed — confidence set to 0.4")

    return state


# ═════════════════════════════════════════════════════════════════════════════
# AGENT 4 — RESOLUTION AGENT
# Layer 2. Groq primary. Three-gate + tool chain execution.
# ═════════════════════════════════════════════════════════════════════════════

def resolution_agent(state: dict) -> dict:
    system_prompt = load_prompt("resolution")
    user_message  = (
        f"Submitter:            {state['submitter']}\n"
        f"Employee ID:          {state['employee_id']}\n"
        f"Resolved account:     {resolve_account_username(state) or 'unknown'}\n"
        f"Root cause:           {state['diagnosis']['root_cause']}\n"
        f"Affected system:      {state['diagnosis']['affected_system']}\n"
        f"Diagnosis confidence: {state['diagnosis']['confidence']}\n"
        f"Category:             {state['intake']['category']}\n"
        f"Ticket summary:       {state['intake']['summary']}\n\n"
        f"Select the tool or tools needed to fully resolve this issue."
    )

    raw = call_llm(
        primary_name="groq",  primary_model=MODELS["resolution_primary"],
        fallback_name="groq", fallback_model=MODELS["resolution_fallback"],
        system_prompt=system_prompt, user_message=user_message, max_tokens=600,
    )

    result = safe_parse_json(raw)

    if not result:
        state["resolution"]["status"]      = "escalated"
        state["resolution"]["explanation"] = "Could not parse resolution decision — escalating"
        state["status"] = "escalated"
        append_audit(state, event="resolution_parse_failed", detail="escalating to human")
        return state

    can_fix     = result.get("can_auto_fix", False)
    tool_chain  = normalize_tool_chain_arguments(state, result.get("tool_chain", []))
    confidence  = float(result.get("confidence", 0.0))
    explanation = result.get("explanation", "")

    state["resolution"]["can_auto_fix"] = can_fix
    state["resolution"]["tool_chain"]   = tool_chain
    state["resolution"]["confidence"]   = confidence
    state["resolution"]["explanation"]  = explanation
    state["resolution"]["tool_results"] = []

    # Gate 1
    if not can_fix:
        state["resolution"]["status"] = "escalated"
        state["status"]               = "escalated"
        append_audit(state, event="resolution_escalated", detail="agent assessed as not auto-fixable")
        return state

    # Gate 2
    if confidence < CONFIDENCE_THRESHOLD:
        state["resolution"]["status"] = "escalated"
        state["status"]               = "escalated"
        append_audit(state, event="resolution_escalated",
                     detail=f"confidence {confidence:.2f} below threshold {CONFIDENCE_THRESHOLD}")
        return state

    # Gate 3
    invalid_tools = [s.get("tool") for s in tool_chain if s.get("tool") not in AVAILABLE_TOOLS]
    if invalid_tools:
        state["resolution"]["status"] = "escalated"
        state["status"]               = "escalated"
        append_audit(state, event="resolution_escalated",
                     detail=f"tool(s) not in whitelist: {invalid_tools}")
        return state

    # Execute chain
    chain_succeeded = True

    for step_index, step in enumerate(tool_chain):
        tool_name = step.get("tool")
        args      = step.get("arguments", {})
        tool_fn   = AVAILABLE_TOOLS[tool_name]

        try:
            tool_result = tool_fn(**args)

            state["resolution"]["tool_results"].append({
                "step":                  step_index + 1,
                "tool":                  tool_name,
                "args":                  args,
                "success":               tool_result.get("success"),
                "message":               tool_result.get("message", ""),
                "reason":                tool_result.get("reason", ""),
                "status":                tool_result.get("status"),
                "affected_users":        tool_result.get("affected_users"),
                "previous_status":       tool_result.get("previous_status"),
                "current_status":        tool_result.get("current_status"),
                "freed_gb":              tool_result.get("freed_gb"),
                "was_used_gb":           tool_result.get("was_used_gb"),
                "now_used_gb":           tool_result.get("now_used_gb"),
                "locked":                tool_result.get("locked"),
                "password_expires_days": tool_result.get("password_expires_days"),
            })

            append_audit(state,
                event=f"tool_executed · step {step_index + 1} · {tool_name}",
                detail=f"success: {tool_result.get('success')} — {tool_result.get('message', tool_result.get('reason', ''))}")

            if not tool_result.get("success"):
                chain_succeeded = False
                append_audit(state, event="chain_stopped",
                             detail=f"step {step_index + 1} failed — remaining steps cancelled")
                break

            # Inter-step validation
            if tool_name == "get_service_status" and tool_result.get("status") == "running":
                state["resolution"]["explanation"] = (
                    f"Service '{args.get('service_name')}' is confirmed running "
                    f"with {tool_result.get('affected_users', 0)} users affected. "
                    f"No restart needed — issue may be client-side."
                )
                state["resolution"]["status"] = "auto_resolved"
                state["status"]               = "auto_resolved"
                append_audit(state, event="chain_stopped_early",
                             detail="service already running — restart skipped")
                chain_succeeded = True
                break

            if tool_name == "check_account_status" and not tool_result.get("locked"):
                state["resolution"]["explanation"] = (
                    f"Account '{args.get('username')}' is confirmed active. No unlock needed."
                )
                state["resolution"]["status"] = "auto_resolved"
                state["status"]               = "auto_resolved"
                append_audit(state, event="chain_stopped_early",
                             detail="account already active — unlock skipped")
                chain_succeeded = True
                break

        except Exception as execution_error:
            state["resolution"]["tool_results"].append({
                "step": step_index + 1, "tool": tool_name, "args": args,
                "success": False, "message": "", "reason": str(execution_error),
            })
            chain_succeeded = False
            append_audit(state, event="tool_execution_error",
                         detail=f"step {step_index + 1} · {tool_name} — {str(execution_error)}")
            break

    if chain_succeeded:
        if state["resolution"]["status"] != "auto_resolved":
            state["resolution"]["status"] = "auto_resolved"
            state["status"]               = "auto_resolved"
            append_audit(state, event="chain_complete",
                         detail=f"{len(tool_chain)} tool(s) executed successfully")
    else:
        state["resolution"]["status"] = "failed"
        state["status"]               = "failed"
        failed_steps = [r for r in (state["resolution"]["tool_results"] or []) if not r.get("success")]
        chain_fail_reason = (
            f"step {failed_steps[0]['step']} · {failed_steps[0]['tool']} failed"
            if failed_steps else "tool chain failed"
        )
        append_audit(state, event="resolution_failed", detail=chain_fail_reason)

    return state


# ═════════════════════════════════════════════════════════════════════════════
# AGENT 5 — ESCALATION AGENT
# Layer 3. Conditional — only runs when resolution fails.
# ═════════════════════════════════════════════════════════════════════════════

def escalation_agent(state: dict) -> dict:
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
        primary_name="groq",  primary_model=MODELS["escalation_primary"],
        fallback_name="groq", fallback_model=MODELS["escalation_fallback"],
        system_prompt=system_prompt, user_message=user_message, max_tokens=500,
    )

    result = safe_parse_json(raw)

    if result:
        state["escalation"]["team"]     = result.get("team",     "IT Support")
        state["escalation"]["priority"] = result.get("priority", state["intake"]["severity"])
        state["escalation"]["summary"]  = result.get("summary",  state["intake"]["summary"])
        state["escalation"]["context"]  = result.get("context",  "No additional context available")
        append_audit(state, event="escalated_to_human",
                     detail=f"team: {state['escalation']['team']} · priority: {state['escalation']['priority']}")
    else:
        state["escalation"] = {
            "team": "IT Support", "priority": state["intake"]["severity"],
            "summary": state["intake"]["summary"],
            "context": (f"Auto-escalated. Root cause: {state['diagnosis']['root_cause']}. "
                        f"Confidence: {state['diagnosis']['confidence']}."),
        }
        append_audit(state, event="escalation_fallback",
                     detail="JSON parse failed — conservative defaults applied")

    state["status"] = "escalated"
    return state
