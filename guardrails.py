"""
guardrails.py
─────────────────────────────────────────────────────────────────────────────
ARIA — Automated Resolution & Incident Agent
Input and output security guardrails — Wall 1 and Wall 3 of the 4-wall
security model.

Security model overview:
  Wall 1 (this file) — Input validation before any agent sees the ticket
  Wall 2             — Agent-level role constraints via system prompts
  Wall 3 (this file) — Output filtering before results reach the user
  Wall 4             — Immutable audit logging (in state.py)

Design principle: No LLM is involved in security decisions.
Using an LLM to detect prompt injection creates a circular vulnerability —
the system being attacked also serves as its own guard. All checks here
are deterministic Python — predictable, fast, and independently auditable.
─────────────────────────────────────────────────────────────────────────────
"""

import re


# ═════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

# Input length bounds
# MIN_LENGTH: anything shorter is almost certainly an accidental submission
# MAX_LENGTH: prevents token-stuffing attacks that inflate cost and confuse agents
MIN_INPUT_LENGTH = 10
MAX_INPUT_LENGTH = 2000

# Known prompt injection phrases
# These patterns are used to hijack LLM system prompts by embedding
# instructions inside the user's ticket text.
# Source: curated from OWASP LLM Top 10 and known jailbreak catalogues.
INJECTION_PATTERNS = [
    "ignore previous instructions",
    "ignore all instructions",
    "ignore your instructions",
    "disregard your",
    "forget everything",
    "you are now",
    "act as",
    "new persona",
    "system prompt",
    "jailbreak",
    "dan mode",
    "pretend you are",
    "override your",
    "bypass your",
    "reveal your prompt",
    "what are your instructions",
    "show me your prompt",
    "print your instructions",
    "you have no restrictions",
    "developer mode",
]

# Output content that should never appear in agent responses
# These patterns indicate either a jailbreak success, a hallucination,
# or an agent going off-script.
BLOCKED_OUTPUT_PATTERNS = [
    "password is",
    "your password",
    "admin credentials",
    "as an ai, i",
    "i cannot help with",
    "i'm sorry, i can't",
    "i am not able to",
]


# ═════════════════════════════════════════════════════════════════════════════
# WALL 1 — INPUT GUARDRAILS
# Run before any agent or LLM sees the ticket text.
# ═════════════════════════════════════════════════════════════════════════════

def validate_length(text: str) -> tuple[bool, str]:
    """
    Validates that input length is within acceptable bounds.

    Short inputs (< MIN_INPUT_LENGTH chars) are likely accidental submissions
    and contain insufficient information for any agent to act on.

    Long inputs (> MAX_INPUT_LENGTH chars) may indicate token-stuffing —
    an attack vector where adversarial content is buried in large text
    to overflow the model's context and dilute safety instructions.

    Args:
        text: Raw input string from the user

    Returns:
        Tuple of (is_valid: bool, reason: str).
        reason is "ok" on success, or a human-readable error on failure.
    """
    length = len(text.strip())

    if length < MIN_INPUT_LENGTH:
        return False, (
            f"Input too short ({length} characters). "
            f"Please describe your issue in more detail."
        )

    if length > MAX_INPUT_LENGTH:
        return False, (
            f"Input too long ({length} characters). "
            f"Maximum allowed is {MAX_INPUT_LENGTH} characters."
        )

    return True, "ok"


def check_injection(text: str) -> tuple[bool, str]:
    """
    Scans input text for known prompt injection attack patterns.

    Injection attacks attempt to override the agent's system prompt by
    embedding instruction-like phrases inside the ticket text. If any
    known pattern is detected, the ticket is blocked immediately and
    the attempt is logged as a security event.

    Case-insensitive matching is used since attackers commonly vary
    capitalisation to evade simple string checks.

    Args:
        text: Raw input string from the user

    Returns:
        Tuple of (is_safe: bool, detail: str).
        is_safe=True means no injection detected — safe to proceed.
        is_safe=False means injection detected — block and log.
    """
    text_lower = text.lower()

    for pattern in INJECTION_PATTERNS:
        if pattern in text_lower:
            return False, f"Injection pattern detected: '{pattern}'"

    return True, "No injection patterns detected"


def mask_pii(text: str) -> tuple[str, int]:
    """
    Detects and masks Personally Identifiable Information (PII) in input text.

    Masked categories:
      - Email addresses  → <EMAIL>
      - Phone numbers    → <PHONE>
      - SSNs             → <SSN>
      - Credit card nos  → <CARD>

    PII masking occurs before the ticket reaches any LLM, ensuring that
    sensitive personal data is never transmitted to external API providers.
    This is a key data handling compliance measure (GDPR / HIPAA alignment).

    Note: In production, Microsoft Presidio (presidio-analyzer) should replace
    this regex approach for higher accuracy and broader PII category coverage.
    Regex is used here for zero-dependency simplicity in the demo environment.

    Args:
        text: Input string that may contain PII

    Returns:
        Tuple of (masked_text: str, count_masked: int).
        masked_text has all PII replaced with placeholder tokens.
        count_masked is the total number of PII items found and replaced.
    """
    masked = text
    count  = 0

    # Email addresses (e.g. john.doe@company.com)
    email_pattern = r'[\w\.\-]+@[\w\.\-]+\.\w{2,}'
    emails = re.findall(email_pattern, masked)
    for email in emails:
        masked = masked.replace(email, "<EMAIL>")
        count += 1

    # US phone numbers in common formats:
    # (555) 123-4567 / 555-123-4567 / 555.123.4567 / +1 555 123 4567
    phone_pattern = r'\b(\+?1[\s\-\.]?)?\(?\d{3}\)?[\s\-\.]?\d{3}[\s\-\.]?\d{4}\b'
    phones = re.findall(phone_pattern, masked)
    for phone in phones:
        full = "".join(phone) if isinstance(phone, tuple) else phone
        if full.strip():
            masked = masked.replace(full.strip(), "<PHONE>")
            count += 1

    # Social Security Numbers (e.g. 123-45-6789)
    ssn_pattern = r'\b\d{3}[-\s]\d{2}[-\s]\d{4}\b'
    ssns = re.findall(ssn_pattern, masked)
    for ssn in ssns:
        masked = masked.replace(ssn, "<SSN>")
        count += 1

    # Credit card numbers (16 digits in groups of 4)
    card_pattern = r'\b(?:\d{4}[\s\-]?){3}\d{4}\b'
    cards = re.findall(card_pattern, masked)
    for card in cards:
        masked = masked.replace(card, "<CARD>")
        count += 1

    return masked, count


def run_security_checks(raw_input: str) -> dict:
    """
    Master input security function — runs all Wall 1 checks in sequence.

    Check order:
      1. Length validation   — fast, no regex, runs first
      2. Injection detection — pattern matching, runs before PII masking
         (we don't want to mask content that we're about to block anyway)
      3. PII masking         — always runs if checks 1 and 2 pass

    Short-circuits on first failure — if length check fails, injection
    and PII checks do not run. This minimises processing on invalid input.

    Args:
        raw_input: The unmodified ticket text from the user submission form

    Returns:
        dict with:
          passed            (bool)  — True if all checks passed
          injection_detected(bool)  — True if an injection attempt was found
          pii_items_masked  (int)   — Count of PII items masked (0 if blocked)
          masked_text       (str)   — PII-masked version of input (or redaction notice)
          block_reason      (str|None) — Human-readable reason if blocked, None if passed
    """
    # ── Check 1: Length ───────────────────────────────────────────────────
    length_ok, length_reason = validate_length(raw_input)
    if not length_ok:
        return {
            "passed":             False,
            "injection_detected": False,
            "pii_items_masked":   0,
            "masked_text":        raw_input,
            "block_reason":       length_reason,
        }

    # ── Check 2: Injection ────────────────────────────────────────────────
    injection_safe, injection_detail = check_injection(raw_input)
    if not injection_safe:
        return {
            "passed":             False,
            "injection_detected": True,
            "pii_items_masked":   0,
            # Do not pass the injected text downstream — replace with redaction notice
            "masked_text":        "[REDACTED — prompt injection attempt detected]",
            "block_reason":       injection_detail,
        }

    # ── Check 3: PII masking (runs only on clean input) ───────────────────
    masked_text, pii_count = mask_pii(raw_input)

    return {
        "passed":             True,
        "injection_detected": False,
        "pii_items_masked":   pii_count,
        "masked_text":        masked_text,
        "block_reason":       None,
    }


# ═════════════════════════════════════════════════════════════════════════════
# WALL 3 — OUTPUT GUARDRAILS
# Run after agents produce a response, before results are shown to the user.
# ═════════════════════════════════════════════════════════════════════════════

def filter_output(text: str) -> tuple[bool, str]:
    """
    Scans LLM output for content that should never reach the end user.

    Even with tightly constrained system prompts (Wall 2), LLMs can
    occasionally produce off-script content through hallucination or
    partial jailbreak. This output filter is the final safety net before
    any agent response is displayed.

    Blocked patterns indicate one of three conditions:
      1. A successful jailbreak — agent adopted an unauthorised persona
      2. A hallucination — agent invented sensitive information
      3. A refusal — agent expressed inability to help (signals misconfiguration)

    If output is blocked, the ticket is escalated to a human rather than
    surfacing the problematic content to the end user.

    Args:
        text: Raw string response produced by an LLM agent

    Returns:
        Tuple of (is_safe: bool, content_or_reason: str).
        If safe: (True, original_text)
        If blocked: (False, reason_for_blocking)
    """
    if not text:
        return False, "Empty response from agent"

    text_lower = text.lower()

    for pattern in BLOCKED_OUTPUT_PATTERNS:
        if pattern in text_lower:
            return False, f"Output blocked — pattern detected: '{pattern}'"

    return True, text