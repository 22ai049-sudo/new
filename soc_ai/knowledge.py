MITRE_KNOWLEDGE = {
    "T1110": "Brute Force: enforce MFA, lockout policy, and source IP controls.",
    "T1566": "Phishing: isolate endpoint, revoke sessions, and reset credentials.",
    "T1595": "Active Scanning: rate-limit and block suspicious scanner ranges.",
    "T1078": "Valid Accounts misuse: rotate secrets and review privileged account use.",
    "T1059": "Command and Scripting Interpreter: investigate host process tree quickly.",
}

POLICY_RULES = {
    "blocked_keywords": ["wipe", "delete all", "shutdown all", "format disk"],
    "require_human_review_severity": ["critical"],
    "max_auto_risk": 0.75,
}
