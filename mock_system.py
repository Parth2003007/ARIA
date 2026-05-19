"""
mock_system.py
─────────────────────────────────────────────────────────────────────────────
ARIA — Automated Resolution & Incident Agent
Simulated IT infrastructure for demo and development purposes.

What this file represents:
  In a production deployment, ARIA would connect to real enterprise systems:
    - Microsoft Active Directory / Azure AD  (user accounts)
    - ServiceNow / Jira Service Management  (ticket routing)
    - Nagios / Datadog / Zabbix             (service monitoring)
    - SCCM / Intune                         (software deployment)
    - PagerDuty / OpsGenie                  (on-call notification)

  In this prototype, all of those systems are represented by a single
  Python dictionary (SYSTEM_STATE) that tools read from and write to.
  The tool function signatures, return contracts, and agent logic are
  identical to what would be used against real APIs. Swapping from mock
  to production is a tool-layer change only — agents require no modification.

State structure:
  users    → Active Directory accounts (locked status, password expiry)
  services → Running services (status, affected user count)
  disk     → Storage drives (used / total GB)
  software → Per-user installed software registry
  ticket_counter → Auto-incrementing ID generator

Demo state:
  Several users and services are intentionally pre-broken to provide
  meaningful auto-resolution demos (locked accounts, crashed services,
  full disks). The reset_system() function restores this broken state
  between demo runs.
─────────────────────────────────────────────────────────────────────────────
"""

import copy


# ═════════════════════════════════════════════════════════════════════════════
# SYSTEM STATE
# Single source of truth for the mock IT environment.
# All tool functions in tools.py read from and write to this dict.
# No other file should mutate this directly.
# ═════════════════════════════════════════════════════════════════════════════

SYSTEM_STATE: dict = {

    # ── Users (Active Directory equivalent) ───────────────────────────────
    # locked=True  → user cannot log in (account lockout policy triggered)
    # locked=False → user account is active and accessible
    # password_expires_days → days remaining before forced password change
    # department → used by Escalation agent to route tickets correctly
    "users": {
        "john.doe":   {"locked": True,  "password_expires_days": 3,  "department": "Sales"},
        "jane.smith": {"locked": False, "password_expires_days": 30, "department": "Engineering"},
        "bob.jones":  {"locked": False, "password_expires_days": 90, "department": "Finance"},
        "sara.chen":  {"locked": True,  "password_expires_days": 0,  "department": "HR"},
    },

    # ── Services (monitoring system equivalent) ───────────────────────────
    # status: "running" | "degraded" | "crashed"
    # affected_users: number of employees currently impacted by this service state
    # The Diagnosis agent uses affected_users to assess incident severity.
    "services": {
        "vpn":      {"status": "crashed",  "affected_users": 47},
        "email":    {"status": "running",  "affected_users": 0},
        "database": {"status": "running",  "affected_users": 0},
        "wifi":     {"status": "degraded", "affected_users": 12},
        "printing": {"status": "crashed",  "affected_users": 8},
    },

    # ── Disk drives (storage management equivalent) ───────────────────────
    # used_gb / total_gb → current and maximum capacity in gigabytes
    # C:/ is intentionally at 95% to trigger the critical disk demo ticket.
    "disk": {
        "C:/": {"used_gb": 95,  "total_gb": 100},
        "D:/": {"used_gb": 40,  "total_gb": 500},
        "E:/": {"used_gb": 800, "total_gb": 1000},
    },

    # ── Software registry (SCCM / Intune equivalent) ─────────────────────
    # List of installed software per user.
    # install_software() appends to these lists.
    # The Resolution agent checks here before attempting an installation.
    "software": {
        "john.doe":   ["Microsoft Office", "Chrome", "Slack"],
        "jane.smith": ["Chrome", "Zoom", "VS Code"],
        "bob.jones":  ["Microsoft Office", "Chrome", "QuickBooks"],
        "sara.chen":  ["Microsoft Office", "Chrome"],
    },

    # ── Ticket counter ────────────────────────────────────────────────────
    # Auto-incremented by get_next_ticket_id() on every new ticket submission.
    # Produces formatted IDs: TKT-001, TKT-002, TKT-003 ...
    "ticket_counter": 0,
}


# ═════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# Read-only utilities for state access and demo management.
# These do not modify SYSTEM_STATE except for get_next_ticket_id()
# and reset_system() which are both intentional mutations.
# ═════════════════════════════════════════════════════════════════════════════

def get_next_ticket_id() -> str:
    """
    Generates a unique, human-readable ticket ID for each submission.

    Increments the ticket counter atomically and formats it with
    zero-padding to produce consistent 3-digit IDs.

    Returns:
        Formatted ticket ID string, e.g. "TKT-001", "TKT-042", "TKT-100"
    """
    SYSTEM_STATE["ticket_counter"] += 1
    return f"TKT-{SYSTEM_STATE['ticket_counter']:03d}"


def get_system_snapshot() -> dict:
    """
    Returns a deep copy of the current system state for UI display.

    Uses deep copy (not shallow copy) to prevent the Streamlit UI from
    accidentally holding a reference to the live state object. If the UI
    mutated a shallow copy, it would silently corrupt the real state.

    The snapshot covers users, services, and disk only — software is
    excluded from the dashboard panel as it is not visually relevant
    for demo purposes.

    Returns:
        Deep-copied dict containing users, services, and disk sections
    """
    return copy.deepcopy({
        "users":    SYSTEM_STATE["users"],
        "services": SYSTEM_STATE["services"],
        "disk":     SYSTEM_STATE["disk"],
    })


def reset_system() -> None:
    """
    Resets the mock system back to its pre-demo broken state.

    Called by the "Reset demo system" button in the Streamlit UI.
    Allows the presenter to re-run demo tickets without restarting
    the application or losing the ticket counter history.

    What gets reset:
      - Locked accounts (john.doe, sara.chen) → locked again
      - Crashed services (vpn, printing) → crashed again
      - Degraded services (wifi) → degraded again
      - Full disk (C:/) → back to 95 GB used

    What does NOT get reset:
      - Ticket counter — preserved so IDs remain unique across the session
      - Software registry — not modified by any demo ticket
    """
    # Restore locked user accounts
    SYSTEM_STATE["users"]["john.doe"]["locked"]  = True
    SYSTEM_STATE["users"]["sara.chen"]["locked"] = True

    # Restore password expiry for john.doe (near-expiry demo scenario)
    SYSTEM_STATE["users"]["john.doe"]["password_expires_days"] = 3
    SYSTEM_STATE["users"]["sara.chen"]["password_expires_days"] = 0

    # Restore service states
    SYSTEM_STATE["services"]["vpn"]["status"]        = "crashed"
    SYSTEM_STATE["services"]["vpn"]["affected_users"] = 47
    SYSTEM_STATE["services"]["wifi"]["status"]       = "degraded"
    SYSTEM_STATE["services"]["wifi"]["affected_users"] = 12
    SYSTEM_STATE["services"]["printing"]["status"]   = "crashed"
    SYSTEM_STATE["services"]["printing"]["affected_users"] = 8

    # Restore critical disk state
    SYSTEM_STATE["disk"]["C:/"]["used_gb"] = 95