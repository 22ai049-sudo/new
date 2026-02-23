from __future__ import annotations

from dataclasses import dataclass


@dataclass
class VerificationResult:
    approved: list[str]
    rejected: list[dict[str, str]]


class CommandVerifier:
    """Enforces command allow-list and unsafe pattern rejection."""

    WHITELIST_PREFIXES = (
        "iptables ",
        "ufw ",
        "ipset ",
        "echo ",
        "cat ",
        "ss ",
    )

    UNSAFE_KEYWORDS = (
        "rm -rf",
        "mkfs",
        "shutdown",
        "reboot",
        "> /dev/sd",
        "curl | sh",
        "wget | sh",
        "dd if=",
    )

    def verify(self, commands: list[str]) -> VerificationResult:
        approved: list[str] = []
        rejected: list[dict[str, str]] = []

        for cmd in commands:
            normalized = cmd.strip().lower()
            if any(keyword in normalized for keyword in self.UNSAFE_KEYWORDS):
                rejected.append({"command": cmd, "reason": "unsafe_command_rejected"})
                continue

            if not normalized.startswith(self.WHITELIST_PREFIXES):
                rejected.append({"command": cmd, "reason": "not_in_whitelist"})
                continue

            approved.append(cmd)

        return VerificationResult(approved=approved, rejected=rejected)
