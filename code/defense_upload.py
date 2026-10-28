from __future__ import annotations

import re

# Helpers
_READ_TOOLS = ("search_emails", "get_unread_emails", "get_received_emails")
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍﻿"), None)
_CODE_RE = re.compile(r"\b\d{6}\b")


# Concatenate everything the email-read tools returned so far (untrusted content).
def _read_text(call_history: list) -> str:
    return "\n".join(
        str(c["output"]) for c in call_history if c["tool"] in _READ_TOOLS
    )

# Canonicalize a string so obfuscation tricks collapse for substring comparison.
def _canon(text: str) -> str:
    s = str(text).lower().translate(_ZERO_WIDTH)
    for a in ("(at)", "[at]", "{at}", " at "):
        s = s.replace(a, "@")
    for d in ("(dot)", "[dot]", "{dot}", " dot "):
        s = s.replace(d, ".")
    return re.sub(r"\s+", "", s)


# Techniques — each guard returns True when it TRIGGERS (detects an attack) and False when clean.
# Baseline: trigger when a send_email recipient appears literally in read email content.
def recipient_source_guard(env, stage, tool_name, read_text, recipients):
    if stage == "post":
        return False
    if tool_name == "send_email":
        for recipient in recipients:
            if recipient in read_text:
                return True
    return False


# Trigger when a send_email recipient (after de-obfuscation) appears in read email content.
def canonical_source_guard(env, stage, tool_name, read_text, recipients):
    if stage == "post":
        return False
    if tool_name != "send_email":
        return False

    read_canon = _canon(read_text)
    for recipient in recipients:
        recipient_canon = _canon(recipient)
        if recipient_canon and recipient_canon in read_canon:
            return True
    return False


# Trigger when send_email body carries a 6-digit code seen in a read email to a non-user-authorized recipient.
def code_exfiltration_guard(env, stage, tool_name, tool_input, read_text, recipients):
    if stage == "post":
        return False
    if tool_name != "send_email":
        return False

    body = str(tool_input.get("body", ""))
    user_canon = _canon(getattr(env, "user_message", ""))
    # at least one recipient was named by the user themselves -> an authorized send
    recipient_authorized_by_user = any(
        _canon(recipient) in user_canon for recipient in recipients
    )
    for code in _CODE_RE.findall(body):
        # the code in the outgoing body was actually read from an email (not user-typed)
        code_came_from_read_email = code in read_text
        # trigger only when a seen code is leaving to a recipient the user never asked for
        if code_came_from_read_email and not recipient_authorized_by_user:
            return True
    return False


def defend(env, stage, tool_name, tool_input, tool_output, call_history):
    recipients = [str(r) for r in (tool_input.get("recipients") or []) if r]
    read_text = _read_text(call_history)

    if recipient_source_guard(env, stage, tool_name, read_text, recipients):
        return False
    if canonical_source_guard(env, stage, tool_name, read_text, recipients):
        return False
    if code_exfiltration_guard(env, stage, tool_name, tool_input, read_text, recipients):
        return False
    return True
