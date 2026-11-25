from __future__ import annotations

import json
import re
import unicodedata
from functools import cached_property

# Constants
_READ_TOOLS = ("search_emails", "get_unread_emails", "get_received_emails")
# zero-width / invisible chars: ZWSP, ZWNJ, ZWJ, BOM, word joiner, soft hyphen, Mongolian vowel separator
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍﻿⁠­᠎"), None)
_BRACKET_AT_RE = re.compile(r"[(\[{<]\s*at\s*[)\]}>]")
_BRACKET_DOT_RE = re.compile(r"[(\[{<]\s*dot\s*[)\]}>]")
# Chinese spelled-out "dot" between ASCII address parts, e.g. "dave点gmail点com"
_CN_DOT_RE = re.compile(r"(?<=[a-z0-9])(?:点|句点|點)(?=[a-z0-9])")
# no \b: CJK chars are \w, so "验证码463820" has no word boundary before the digits
_CODE_RE = re.compile(r"(?<!\d)\d{6}(?!\d)")
_DIGIT_RUN_RE = re.compile(r"\d{4,}")
_SECRET_RE = re.compile(r"(?<![0-9A-Za-z])(?=[0-9A-Za-z-]*\d)[0-9A-Za-z-]{4,12}(?![0-9A-Za-z])")
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_STRICT_EMAIL_RE = re.compile(r"^[^@\s,;<>]+@[^@\s,;<>]+\.[^@\s,;<>]+$")

_SEND_WORDS = ("转发", "发送", "发给", "发到", "发至", "寄给", "抄送", "转交", "提交", "报送", "上报", "同步给",
               "回复至", "告知", "交给", "forward", "send", "mail to", "email to", "share", "submit",
               "report to", "reply to", "cc")
_SECRET_WORDS = ("验证码", "密码", "code", "password", "otp", "token", "pin")
_SECRET_SENDERS = ("security", "noreply", "no-reply", "verify")
# ASCII keywords up to this length must match as whole words (see _mentions)
_SHORT_WORD_LEN = 4
# single letters separated by spaces, e.g. "c o d e" -> joined to "code"
_SPACED_LETTERS_RE = re.compile(r"(?<![a-z])([a-z])\s+(?=[a-z](?![a-z]))")

# Left in place of every line the sanitizer drops. call_history only keeps sanitized outputs,
# so this marker is how later calls learn an injection was seen earlier in the request.
_REMOVED_MARK = "[已移除可疑指令 / suspicious instruction removed]"
_REDACTED_MARK = "[REDACTED]"


# Helpers

# Email list from a read tool's output: a JSON string locally, but accept an already-decoded list too.
# Dicts are copied so the sanitizers never mutate the caller's raw output.
def _parse_items(tool_output) -> list | None:
    if isinstance(tool_output, list):
        items = tool_output
    else:
        try:
            items = json.loads(tool_output)
        except (TypeError, ValueError):
            return None
    if not isinstance(items, list):
        return None
    return [dict(item) if isinstance(item, dict) else item for item in items]

# Parse every email object the read tools returned so far, keyed by id.
def _read_emails(call_history: list) -> dict:
    emails = {}
    for call in call_history:
        if call["tool"] in _READ_TOOLS:
            for email in _parse_items(call["output"]) or []:
                if isinstance(email, dict):
                    emails[str(email.get("id"))] = email
    return emails

# Fold fullwidth/compat forms (NFKC), lowercase, and strip invisible chars.
def _fold(text) -> str:
    return unicodedata.normalize("NFKC", str(text)).lower().translate(_ZERO_WIDTH)

# Canonicalize a string so address obfuscation tricks collapse for substring comparison.
def _canon(text) -> str:
    # NFKC folds "＠" -> "@", "．" -> ".", "（at）" -> "(at)"
    normalized = _fold(text)
    # bracketed forms first, tolerating inner spaces: "(at)", "[ at ]", "{dot}", "<dot>"
    normalized = _BRACKET_AT_RE.sub("@", normalized)
    normalized = _BRACKET_DOT_RE.sub(".", normalized)
    normalized = normalized.replace(" at ", "@").replace(" dot ", ".")
    normalized = re.sub(r"\s+", "", normalized).replace("艾特", "@")
    return _CN_DOT_RE.sub(".", normalized)

# Keyword test that survives "Ｆorward", "转​发", "for ward" and "c o d e".
# Short ASCII words must stand alone ("cc" not in "account", "pin" not in "shopping");
# longer words and Chinese match without whitespace, so split-up spellings still count.
def _mentions(text, words) -> bool:
    folded = _fold(text)
    squashed = re.sub(r"\s+", "", folded)
    letters_joined = _SPACED_LETTERS_RE.sub(r"\1", folded)
    for word in words:
        if word.isascii() and len(word) <= _SHORT_WORD_LEN:
            if re.search(rf"(?<![a-z]){re.escape(word)}(?![a-z])", letters_joined):
                return True
        elif word.replace(" ", "") in squashed:
            return True
    return False

# 6-digit codes plus alphanumeric/dash tokens carrying at least 4 digits.
def _code_like(text: str) -> set:
    tokens = set(_CODE_RE.findall(text))
    tokens.update(
        token for token in _SECRET_RE.findall(text)
        if sum(char.isdigit() for char in token) >= 4
    )
    return tokens

def _is_security_mail(email: dict) -> bool:
    sender = str(email.get("sender", "")).lower()
    return (any(marker in sender for marker in _SECRET_SENDERS)
            or _mentions(email.get("subject", ""), _SECRET_WORDS))

# Text that points the reader at an address other than the email's own sender and either
# tells them to send something there or mentions a secret.
def _is_injection_text(text: str, sender_canon: str) -> bool:
    foreign_addresses = [address for address in _EMAIL_RE.findall(_canon(text)) if address != sender_canon]
    return bool(foreign_addresses) and (_mentions(text, _SEND_WORDS) or _mentions(text, _SECRET_WORDS))

# Indices of body lines to drop. Adjacent pairs are also checked joined, which catches
# an instruction whose address sits on the next line or is split across a line break.
def _injection_lines(lines: list, sender_canon: str) -> set:
    flagged = {index for index, line in enumerate(lines) if _is_injection_text(line, sender_canon)}
    for index in range(len(lines) - 1):
        pair = lines[index] + "\n" + lines[index + 1]
        if index not in flagged and index + 1 not in flagged and _is_injection_text(pair, sender_canon):
            flagged.update((index, index + 1))
    return flagged

def _has_injection(emails: dict) -> bool:
    return any(
        _REMOVED_MARK in str(email.get("body", ""))
        or _injection_lines(str(email.get("body", "")).split("\n"), _canon(email.get("sender", "")))
        for email in emails.values()
    )


# Request context

# Everything the guards need about the current request. Fields are computed lazily, once per call,
# so each stage only pays for what its guards actually read.
class _RequestContext:
    def __init__(self, tool_input: dict, call_history: list):
        self._call_history = call_history
        raw_recipients = tool_input.get("recipients")
        self.recipients = (
            [str(recipient) for recipient in raw_recipients if recipient]
            if isinstance(raw_recipients, list) else []
        )

    # everything the read tools returned so far (untrusted content)
    @cached_property
    def read_text(self) -> str:
        return "\n".join(
            str(call["output"]) for call in self._call_history if call["tool"] in _READ_TOOLS
        )

    @cached_property
    def read_canon(self) -> str:
        return _canon(self.read_text)

    @cached_property
    def emails(self) -> dict:
        return _read_emails(self._call_history)

    @cached_property
    def injection_seen(self) -> bool:
        return _has_injection(self.emails)

    @cached_property
    def sent_before(self) -> bool:
        return any(call["tool"] == "send_email" for call in self._call_history)


# Guards — each returns True when it TRIGGERS (detects an attack) and False when clean.

# send_email guards

# Trigger when recipients is malformed: not a list of plain, well-formed addresses.
def recipient_shape_guard(_context: _RequestContext, tool_input: dict) -> bool:
    raw_recipients = tool_input.get("recipients")
    if not isinstance(raw_recipients, list) or not raw_recipients:
        return True
    return not all(
        isinstance(recipient, str) and _STRICT_EMAIL_RE.match(recipient.strip())
        for recipient in raw_recipients
    )

# Trigger when a second send_email is attempted within one user request.
def send_count_guard(context: _RequestContext, _tool_input: dict) -> bool:
    return context.sent_before

# Trigger when a recipient (after de-obfuscation) appears in read email content.
# Backstop: the sanitizer already removes instruction lines, so this fires when an address survives elsewhere.
def canonical_source_guard(context: _RequestContext, _tool_input: dict) -> bool:
    return any(
        _canon(recipient) and _canon(recipient) in context.read_canon
        for recipient in context.recipients
    )

# Trigger when the outgoing mail carries a secret from security/verification mail (as a substring,
# so "abcdefghijklm1463820" still counts), a 6-digit code read from any email, or — once an injection
# was seen — anything code-like at all, since redaction removes the code from history.
def read_code_leak_guard(context: _RequestContext, tool_input: dict) -> bool:
    outgoing = str(tool_input.get("subject", "")) + "\n" + str(tool_input.get("body", ""))
    security_secrets = set().union(*(
        _code_like(str(email.get("body", "")))
        for email in context.emails.values() if _is_security_mail(email)
    ))
    if any(secret in outgoing for secret in security_secrets):
        return True
    if context.injection_seen and (_DIGIT_RUN_RE.search(outgoing) or _code_like(outgoing)):
        return True
    return any(code in context.read_text for code in _CODE_RE.findall(outgoing))


# delete_email guards

# Trigger when deleting a security/verification email — or an email never read — in a request that
# already shows attack signs (a send was attempted, or an injection was seen), i.e. covering the tracks.
def evidence_delete_guard(context: _RequestContext, tool_input: dict) -> bool:
    target = context.emails.get(str(tool_input.get("email_id", "")))
    if target is None:
        return context.injection_seen
    if not _is_security_mail(target):
        return False
    return context.sent_before or context.injection_seen


_GUARDS = {
    "send_email": (recipient_shape_guard, send_count_guard, canonical_source_guard, read_code_leak_guard),
    "delete_email": (evidence_delete_guard,),
}


# Sanitizers — post-stage rewrites of read-tool output. Each mutates items and returns True when anything changed.

# Replace lines that tell the reader to send something to a foreign address with _REMOVED_MARK.
def injection_sanitizer(items: list) -> bool:
    changed = False
    for email in items:
        if not isinstance(email, dict):
            continue
        lines = str(email.get("body", "")).split("\n")
        dropped = _injection_lines(lines, _canon(email.get("sender", "")))
        if not dropped:
            continue
        changed = True
        kept = []
        for index, line in enumerate(lines):
            if index not in dropped:
                kept.append(line)
            elif not kept or kept[-1] != _REMOVED_MARK:  # one marker per removed block
                kept.append(_REMOVED_MARK)
        email["body"] = "\n".join(kept)
    return changed

# Once an injection was seen in this request, mask secrets in security/verification mail
# so the agent never learns the code.
def code_redaction_sanitizer(items: list) -> bool:
    changed = False
    for email in items:
        if not isinstance(email, dict) or not _is_security_mail(email):
            continue
        body = str(email.get("body", ""))
        for token in _code_like(body):
            body = body.replace(token, _REDACTED_MARK)
        if body != email.get("body"):
            email["body"] = body
            changed = True
    return changed


# Entry point

def _defend(_env, stage, tool_name, tool_input, tool_output, call_history):
    context = _RequestContext(tool_input, call_history)

    if stage == "post":
        items = _parse_items(tool_output)
        if tool_name not in _READ_TOOLS or items is None:
            return True
        sanitized = injection_sanitizer(items)
        # injection in this output, or a marker left by an earlier call in this request
        redacted = (sanitized or context.injection_seen) and code_redaction_sanitizer(items)
        return items if (sanitized or redacted) else True

    return not any(guard(context, tool_input) for guard in _GUARDS.get(tool_name, ()))


# Fail closed: the env treats a raised exception as "allow", so catch it here and block risky tools.
def defend(env, stage, tool_name, tool_input, tool_output, call_history):
    try:
        return _defend(env, stage, tool_name, tool_input, tool_output, call_history)
    except Exception:
        return stage == "post" or tool_name not in ("send_email", "delete_email")
