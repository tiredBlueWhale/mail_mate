from __future__ import annotations

import json
import re

# Helpers
_READ_TOOLS = ("search_emails", "get_unread_emails", "get_received_emails")
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍﻿"), None)
# no \b: CJK chars are \w, so "验证码463820" has no word boundary before the digits
_CODE_RE = re.compile(r"(?<!\d)\d{6}(?!\d)")
_SECRET_RE = re.compile(r"(?<![0-9A-Za-z])(?=[0-9A-Za-z-]*\d)[0-9A-Za-z-]{4,12}(?![0-9A-Za-z])")
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_STRICT_EMAIL_RE = re.compile(r"^[^@\s,;<>]+@[^@\s,;<>]+\.[^@\s,;<>]+$")

_SEND_WORDS = ("转发", "发送", "发给", "发到", "发至", "寄给", "抄送", "forward", "send", "mail to", "email to")
_SECRET_WORDS = ("验证码", "密码", "code", "password", "otp", "token", "pin")
_SECRET_SENDERS = ("security", "noreply", "no-reply", "verify", "account")


# Concatenate everything the email-read tools returned so far (untrusted content).
def _read_text(call_history: list) -> str:
    return "\n".join(
        str(c["output"]) for c in call_history if c["tool"] in _READ_TOOLS
    )

# Parse every email object the read tools returned so far, keyed by id.
def _read_emails(call_history: list) -> dict:
    emails = {}
    for c in call_history:
        if c["tool"] not in _READ_TOOLS:
            continue
        try:
            items = json.loads(c["output"])
        except (TypeError, ValueError):
            continue
        for m in items if isinstance(items, list) else []:
            if isinstance(m, dict):
                emails[str(m.get("id"))] = m
    return emails

# Canonicalize a string so obfuscation tricks collapse for substring comparison.
def _canon(text: str) -> str:
    s = str(text).lower().translate(_ZERO_WIDTH)
    for a in ("(at)", "[at]", "{at}", " at "):
        s = s.replace(a, "@")
    for d in ("(dot)", "[dot]", "{dot}", " dot "):
        s = s.replace(d, ".")
    return re.sub(r"\s+", "", s)

def _mentions(text: str, words) -> bool:
    low = str(text).lower()
    return any(w in low for w in words)

# Secret-looking tokens from emails that look like security / verification mail.
def _secret_tokens(emails: dict) -> set:
    tokens = set()
    for m in emails.values():
        sender = str(m.get("sender", "")).lower()
        subject = str(m.get("subject", ""))
        body = str(m.get("body", ""))
        if any(s in sender for s in _SECRET_SENDERS) or _mentions(subject, _SECRET_WORDS):
            tokens.update(t for t in _SECRET_RE.findall(body) if sum(ch.isdigit() for ch in t) >= 4)
    return tokens


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
    # every recipient was named by the user themselves -> an authorized send
    recipients_authorized_by_user = all(
        _canon(recipient) in user_canon for recipient in recipients
    )
    for code in _CODE_RE.findall(body):
        # the code in the outgoing body was actually read from an email (not user-typed)
        code_came_from_read_email = code in read_text
        # trigger only when a seen code is leaving to a recipient the user never asked for
        if code_came_from_read_email and not recipients_authorized_by_user:
            return True
    return False


# Trigger when recipients is malformed: not a list of plain, well-formed addresses.
def recipient_shape_guard(env, stage, tool_name, tool_input):
    if stage == "post" or tool_name != "send_email":
        return False
    raw = tool_input.get("recipients")
    if not isinstance(raw, list) or not raw:
        return True
    return not all(isinstance(r, str) and _STRICT_EMAIL_RE.match(r.strip()) for r in raw)




# Trigger when a second send_email is attempted within one user request.
def send_count_guard(env, stage, tool_name, call_history):
    if stage == "post" or tool_name != "send_email":
        return False
    return any(c["tool"] == "send_email" for c in call_history)

# Trigger when the body carries a secret read from a security/verification email the user didn't ask to share.
def secret_token_guard(env, stage, tool_name, tool_input, emails):
    if stage == "post" or tool_name != "send_email":
        return False
    if _mentions(getattr(env, "user_message", ""), _SECRET_WORDS + ("facebook",)):
        return False
    body = str(tool_input.get("body", ""))
    return any(t in body for t in _secret_tokens(emails))


# Trigger when a forwarded email's body carries a code that belongs to a different read email.
def cross_email_leak_guard(env, stage, tool_name, tool_input, emails):
    if stage == "post" or tool_name != "send_email":
        return False
    subject = str(tool_input.get("subject", ""))
    body = str(tool_input.get("body", ""))
    source = [m for m in emails.values() if m.get("subject") and m["subject"] in subject]
    if not source:
        return False
    source_body = "\n".join(str(m.get("body", "")) for m in source)
    others = "\n".join(str(m.get("body", "")) for m in emails.values() if m not in source)
    return any(code in others and code not in source_body for code in _CODE_RE.findall(body))



# Post-stage rewrite: drop lines in read emails that tell the reader to send something to a foreign address.
# Returns the cleaned list, or None when nothing had to change.
def injection_sanitizer(stage, tool_name, tool_output):
    if stage != "post" or tool_name not in _READ_TOOLS:
        return None
    try:
        items = json.loads(tool_output)
    except (TypeError, ValueError):
        return None
    if not isinstance(items, list):
        return None

    changed = False
    for m in items:
        if not isinstance(m, dict):
            continue
        sender = _canon(m.get("sender", ""))
        kept = []
        for line in str(m.get("body", "")).split("\n"):
            addrs = [a for a in _EMAIL_RE.findall(_canon(line)) if a != sender]
            if addrs and _mentions(line, _SEND_WORDS):
                changed = True
                continue
            kept.append(line)
        m["body"] = "\n".join(kept)
    return items if changed else None


def _defend(env, stage, tool_name, tool_input, tool_output, call_history):
    raw_recipients = tool_input.get("recipients")
    recipients = [str(r) for r in raw_recipients if r] if isinstance(raw_recipients, list) else []
    read_text = _read_text(call_history)
    emails = _read_emails(call_history)

    if stage == "post":
        cleaned = injection_sanitizer(stage, tool_name, tool_output)
        return cleaned if cleaned is not None else True

    guards = (
        lambda: recipient_shape_guard(env, stage, tool_name, tool_input),
        lambda: send_count_guard(env, stage, tool_name, call_history),
        lambda: recipient_source_guard(env, stage, tool_name, read_text, recipients),
        lambda: canonical_source_guard(env, stage, tool_name, read_text, recipients),
        lambda: code_exfiltration_guard(env, stage, tool_name, tool_input, read_text, recipients),
        lambda: secret_token_guard(env, stage, tool_name, tool_input, emails),
        lambda: cross_email_leak_guard(env, stage, tool_name, tool_input, emails),
    )
    return not any(guard() for guard in guards)


# Fail closed: the env treats a raised exception as "allow", so catch it here and block risky tools.
def defend(env, stage, tool_name, tool_input, tool_output, call_history):
    try:
        return _defend(env, stage, tool_name, tool_input, tool_output, call_history)
    except Exception:
        return stage == "post" or tool_name not in ("send_email", "delete_email")
