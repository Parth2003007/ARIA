"""
tools.py
─────────────────────────────────────────────────────────────────────────────
ARIA — Automated Resolution & Incident Agent
Auto-remediation tool library for the Resolution agent.

Architecture contract:
  - The LLM (Resolution agent) decides WHICH tool to call and with WHAT args
  - Python executes the tool — the LLM never has direct system access
  - Every tool follows the same return contract: {"success": bool, ...details}
  - Tools never raise exceptions — all errors are caught and returned as dicts
  - Tools only read/write to SYSTEM_STATE — no external side effects in demo

Tool registry (AVAILABLE_TOOLS at bottom of file):
  The Resolution agent can only call tools registered here.
  An unregistered tool name is silently blocked — never executed.
  Adding a new fix = add a function + add it to AVAILABLE_TOOLS.
  No other file needs to change.

Production note:
  In production, each mock SYSTEM_STATE mutation would be replaced with
  a real API call (Active Directory, ServiceNow, systemctl, etc.).
  The function signatures, return contracts, and registry remain identical.
  The agent layer requires zero changes when moving from mock to production.
─────────────────────────────────────────────────────────────────────────────
"""

import os
from datetime import datetime, timezone
from mock_system import SYSTEM_STATE

# Company domain — used in notification messages.
# Loaded from environment so it can be changed per deployment without
# touching source code.
COMPANY_DOMAIN = os.getenv("COMPANY_DOMAIN", "company.com")


# ═════════════════════════════════════════════════════════════════════════════
# ACCOUNT MANAGEMENT TOOLS
# Interact with the users section of SYSTEM_STATE.
# Production equivalent: Microsoft Active Directory API / Azure AD Graph API
# ═════════════════════════════════════════════════════════════════════════════

def check_account_status(username: str) -> dict:
    """
    Reads the current state of a user account without modifying anything.

    Used by the Resolution agent as a pre-check before taking action —
    confirms the account exists and its actual state before committing
    to an unlock or password reset.

    Args:
        username: The account username (e.g. "john.doe")

    Returns:
        dict with success, locked status, password expiry, and department.
        Returns success=False if username not found in system.
    """
    if username not in SYSTEM_STATE["users"]:
        return {
            "success": False,
            "reason":  f"User '{username}' not found in the system",
        }

    user = SYSTEM_STATE["users"][username]
    return {
        "success":               True,
        "username":              username,
        "locked":                user["locked"],
        "password_expires_days": user["password_expires_days"],
        "department":            user["department"],
    }


def unlock_account(username: str) -> dict:
    """
    Unlocks a locked user account, restoring login access.

    Pre-checks:
      - Username must exist in the system
      - Account must currently be locked (idempotency guard)

    Production equivalent:
      Active Directory: Set-ADUser -Identity username -Enabled $true
      Azure AD: PATCH /users/{id} {"accountEnabled": true}

    Args:
        username: The account username to unlock

    Returns:
        dict with success and confirmation message, or failure reason
    """
    if username not in SYSTEM_STATE["users"]:
        return {
            "success": False,
            "reason":  f"User '{username}' not found in the system",
        }

    if not SYSTEM_STATE["users"][username]["locked"]:
        return {
            "success": False,
            "reason":  f"Account '{username}' is already unlocked — no action taken",
        }

    # Mutate system state — production would call AD API here
    SYSTEM_STATE["users"][username]["locked"] = False

    return {
        "success": True,
        "message": f"Account '{username}' has been unlocked successfully",
    }


def send_password_reset(username: str) -> dict:
    """
    Sends a password reset link to the user's registered email address.

    The email address is derived from the username and company domain,
    matching the standard corporate email format (username@domain.com).
    COMPANY_DOMAIN is loaded from the environment variable COMPANY_DOMAIN.

    Production equivalent:
      Azure AD: POST /users/{id}/revokeSignInSessions
      then POST to identity provider's password reset flow

    Args:
        username: The account username requiring a password reset

    Returns:
        dict with success and the email address the reset was sent to
    """
    if username not in SYSTEM_STATE["users"]:
        return {
            "success": False,
            "reason":  f"User '{username}' not found in the system",
        }

    email = f"{username}@{COMPANY_DOMAIN}"

    # Production: call SMTP server or identity provider API
    # Demo: print to console to simulate the outbound notification
    print(f"[MOCK] Password reset email dispatched to {email}")

    return {
        "success": True,
        "message": f"Password reset link sent to {email}",
        "email":   email,
    }


def extend_password_expiry(username: str) -> dict:
    """
    Resets a user's password expiry timer to 90 days from now.

    Used when a user is experiencing login issues caused by an expired
    or near-expiring password. Gives them time to set a new one properly.

    Production equivalent:
      Active Directory: Set-ADUser -PasswordNeverExpires or set pwdLastSet
      Azure AD: PATCH /users/{id} {"passwordPolicies": "None"}

    Args:
        username: The account username whose expiry should be extended

    Returns:
        dict with success, confirmation message, and new expiry in days
    """
    if username not in SYSTEM_STATE["users"]:
        return {
            "success": False,
            "reason":  f"User '{username}' not found in the system",
        }

    SYSTEM_STATE["users"][username]["password_expires_days"] = 90

    return {
        "success":          True,
        "message":          f"Password expiry extended for '{username}'",
        "new_expiry_days":  90,
    }


# ═════════════════════════════════════════════════════════════════════════════
# SERVICE MANAGEMENT TOOLS
# Interact with the services section of SYSTEM_STATE.
# Production equivalent: systemctl (Linux), Windows Service Manager,
# Kubernetes pod restart, cloud provider health management APIs
# ═════════════════════════════════════════════════════════════════════════════

def get_service_status(service_name: str) -> dict:
    """
    Reads the current status of a system service without modifying it.

    Used as a pre-check before restarting — confirms the service is
    actually down before taking action, preventing unnecessary restarts
    of healthy services.

    Args:
        service_name: Name of the service (e.g. "vpn", "email")

    Returns:
        dict with success, current status, and number of affected users
    """
    if service_name not in SYSTEM_STATE["services"]:
        return {
            "success": False,
            "reason":  f"Service '{service_name}' not found in the system",
        }

    svc = SYSTEM_STATE["services"][service_name]
    return {
        "success":        True,
        "service":        service_name,
        "status":         svc["status"],
        "affected_users": svc["affected_users"],
    }


def restart_service(service_name: str) -> dict:
    """
    Restarts a crashed or degraded service, restoring it to running state.

    Also resets affected_users to 0 — once the service is running,
    no users should remain impacted.

    Production equivalent:
      Linux:      subprocess.run(["systemctl", "restart", service_name])
      Windows:    subprocess.run(["net", "start", service_name])
      Kubernetes: kubectl rollout restart deployment/{service_name}

    Args:
        service_name: Name of the service to restart

    Returns:
        dict with success, previous status, and current status
    """
    if service_name not in SYSTEM_STATE["services"]:
        return {
            "success": False,
            "reason":  f"Service '{service_name}' not found in the system",
        }

    previous_status = SYSTEM_STATE["services"][service_name]["status"]

    # Mutate system state — production would call systemctl or equivalent here
    SYSTEM_STATE["services"][service_name]["status"]         = "running"
    SYSTEM_STATE["services"][service_name]["affected_users"] = 0

    return {
        "success":         True,
        "message":         f"Service '{service_name}' restarted successfully",
        "previous_status": previous_status,
        "current_status":  "running",
        "affected_users":  0,
    }


def degrade_to_safe_mode(service_name: str) -> dict:
    """
    Moves a crashed service to degraded (partial functionality) mode.

    More conservative than a full restart — used when:
      - The root cause is unknown and a full restart may cause data loss
      - The service is stateful and needs manual investigation first
      - A human needs to review before full restoration

    In degraded mode, partial functionality is restored while the full
    diagnosis continues in the background by a human agent.

    Args:
        service_name: Name of the service to move to safe mode

    Returns:
        dict with success, previous status, and current status
    """
    if service_name not in SYSTEM_STATE["services"]:
        return {
            "success": False,
            "reason":  f"Service '{service_name}' not found in the system",
        }

    previous_status = SYSTEM_STATE["services"][service_name]["status"]
    SYSTEM_STATE["services"][service_name]["status"] = "degraded"

    return {
        "success":         True,
        "message":         f"Service '{service_name}' moved to safe/degraded mode",
        "previous_status": previous_status,
        "current_status":  "degraded",
    }


# ═════════════════════════════════════════════════════════════════════════════
# DISK MANAGEMENT TOOLS
# Interact with the disk section of SYSTEM_STATE.
# Production equivalent: PowerShell disk cleanup scripts, Linux find+rm,
# cloud storage management APIs
# ═════════════════════════════════════════════════════════════════════════════

def clear_disk_space(drive: str) -> dict:
    """
    Clears temporary files and caches to free approximately 15 GB of space.

    Used for moderate disk usage scenarios (80–94% full).
    Targets safe-to-delete locations: temp folders, log archives,
    browser caches, and Windows Update cleanup.

    Production equivalent:
      Windows: cleanmgr /sagerun, PowerShell Remove-Item -Path $env:TEMP
      Linux:   find /tmp -type f -mtime +7 -delete && journalctl --vacuum-size=1G

    Args:
        drive: Drive identifier (e.g. "C:/", "D:/")

    Returns:
        dict with success, GB freed, and before/after usage figures
    """
    if drive not in SYSTEM_STATE["disk"]:
        return {
            "success": False,
            "reason":  f"Drive '{drive}' not found in the system",
        }

    freed_gb    = 15
    was_used_gb = SYSTEM_STATE["disk"][drive]["used_gb"]
    new_used_gb = max(0, was_used_gb - freed_gb)

    SYSTEM_STATE["disk"][drive]["used_gb"] = new_used_gb

    return {
        "success":     True,
        "message":     f"Standard cleanup completed on {drive} — {freed_gb} GB freed",
        "freed_gb":    freed_gb,
        "was_used_gb": was_used_gb,
        "now_used_gb": new_used_gb,
        "drive":       drive,
    }


def free_up_disk_aggressive(drive: str) -> dict:
    """
    Performs an aggressive cleanup to free approximately 30 GB of space.

    Used for critical disk usage scenarios (95%+ full) where standard
    cleanup is insufficient. Targets additional locations including
    hibernation files, old restore points, and archived logs.

    This tool is intentionally separate from clear_disk_space to prevent
    the Resolution agent from using aggressive cleanup when standard
    cleanup is sufficient — maintaining proportionality of action.

    Production equivalent:
      Windows: Disable hibernation (powercfg /h off), vssadmin delete shadows
      Linux:   docker system prune, apt-get clean, find / -name "*.log" -delete

    Args:
        drive: Drive identifier (e.g. "C:/", "D:/")

    Returns:
        dict with success, GB freed, and before/after usage figures
    """
    if drive not in SYSTEM_STATE["disk"]:
        return {
            "success": False,
            "reason":  f"Drive '{drive}' not found in the system",
        }

    freed_gb    = 30
    was_used_gb = SYSTEM_STATE["disk"][drive]["used_gb"]
    new_used_gb = max(0, was_used_gb - freed_gb)

    SYSTEM_STATE["disk"][drive]["used_gb"] = new_used_gb

    return {
        "success":     True,
        "message":     f"Aggressive cleanup completed on {drive} — {freed_gb} GB freed",
        "freed_gb":    freed_gb,
        "was_used_gb": was_used_gb,
        "now_used_gb": new_used_gb,
        "drive":       drive,
    }


# ═════════════════════════════════════════════════════════════════════════════
# SOFTWARE MANAGEMENT TOOLS
# Interact with the software section of SYSTEM_STATE.
# Production equivalent: SCCM/Intune push deployment, package managers,
# silent install scripts
# ═════════════════════════════════════════════════════════════════════════════

def install_software(username: str, software_name: str) -> dict:
    """
    Installs a software package for a specific user if not already present.

    Pre-checks whether the software is already installed before acting,
    preventing redundant deployments and the audit noise they create.

    Production equivalent:
      SCCM:   Invoke-CMClientNotification -DeviceName hostname -ActionType InstallSoftware
      Intune: PATCH /deviceManagement/managedDevices/{id}
      Linux:  apt-get install -y {package} via SSH

    Args:
        username:      User to install software for
        software_name: Display name of the software package

    Returns:
        dict with success, confirmation, or reason if already installed
    """
    if username not in SYSTEM_STATE["software"]:
        return {
            "success": False,
            "reason":  f"User '{username}' not found in software registry",
        }

    if software_name in SYSTEM_STATE["software"][username]:
        return {
            "success": True,
            "message": f"'{software_name}' is already installed for {username} — no action needed",
            "already_installed": True,
        }

    SYSTEM_STATE["software"][username].append(software_name)

    return {
        "success":   True,
        "message":   f"'{software_name}' installed successfully for {username}",
        "installed": software_name,
        "username":  username,
    }


# ═════════════════════════════════════════════════════════════════════════════
# COMMUNICATION TOOLS
# Trigger outbound notifications to IT teams.
# Production equivalent: Slack webhook, PagerDuty API, ServiceNow incident
# creation, Microsoft Teams webhook
# ═════════════════════════════════════════════════════════════════════════════

def notify_it_team(issue: str, priority: str, context: str) -> dict:
    """
    Notifies the appropriate IT team when human intervention is required.

    Called by the Escalation agent as the final step of a HITL handoff.
    Provides the receiving team with issue summary, priority, and full
    diagnostic context so they can act immediately without re-investigating.

    Production equivalent:
      Slack:      POST to webhook with structured message block
      PagerDuty:  POST /incidents with severity and body
      ServiceNow: POST /api/now/table/incident

    Args:
        issue:    Short description of the issue requiring human attention
        priority: Priority level (low | medium | high | critical)
        context:  Full diagnostic context for the receiving human agent

    Returns:
        dict with success, confirmation message, and UTC timestamp
    """
    timestamp = datetime.now(timezone.utc).isoformat()

    # Production: POST to Slack/PagerDuty/ServiceNow webhook
    # Demo: print to console to simulate outbound notification
    print(f"[MOCK] IT Team notification dispatched — {priority.upper()}: {issue}")

    return {
        "success":   True,
        "message":   "IT team notified with full diagnostic context",
        "timestamp": timestamp,
        "priority":  priority,
        "issue":     issue,
    }


# ═════════════════════════════════════════════════════════════════════════════
# TOOL REGISTRY
# ─────────────────────────────────────────────────────────────────────────────
# The Resolution agent can ONLY call tools registered here.
# Any tool name not in this dict is silently blocked — never executed.
#
# This is the security boundary between LLM decision-making and
# Python execution. The LLM proposes. The whitelist permits.
#
# To add a new auto-fix capability:
#   1. Write a function above following the {"success": bool} contract
#   2. Add it to this dict with a descriptive key
#   3. Update the resolution prompt to include the new tool name and usage
#   That is the complete change set. No other files need modification.
# ═════════════════════════════════════════════════════════════════════════════

AVAILABLE_TOOLS: dict[str, callable] = {
    # Account management
    "check_account_status":    check_account_status,
    "unlock_account":          unlock_account,
    "send_password_reset":     send_password_reset,
    "extend_password_expiry":  extend_password_expiry,

    # Service management
    "get_service_status":      get_service_status,
    "restart_service":         restart_service,
    "degrade_to_safe_mode":    degrade_to_safe_mode,

    # Disk management
    "clear_disk_space":        clear_disk_space,
    "free_up_disk_aggressive": free_up_disk_aggressive,

    # Software management
    "install_software":        install_software,

    # Communication
    "notify_it_team":          notify_it_team,
}