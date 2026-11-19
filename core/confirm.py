"""Bezzy Fase 2, stap 2.3b: time-based confirmation code for dangerous tools.

Python port of the TOTP check on the vault server (RFC 6238, SHA-1, 6 digits, 30 s).
The secret lives only in the TOTP_SECRET environment variable (base32). Tools listed in
CONFIRM_TOOLS (comma separated) need a 6-digit code from Sjoerd's authenticator app.
With CONFIRM_TOOLS empty nothing changes, so clearing it is the rollback.
Fails closed: a code is required but no secret configured means the call is refused.
"""

import base64
import contextvars
import hashlib
import hmac
import os
import struct
import time
from typing import Any, Dict, Optional, Set

CONFIRM_TOOLS: Set[str] = {
    s.strip() for s in os.getenv("CONFIRM_TOOLS", "").split(",") if s.strip()
}
TOTP_SECRET: str = os.getenv("TOTP_SECRET", "")

_failures = 0
_locked_until = 0.0
_last_accepted_step = -1


def _base32_key(secret: str) -> bytes:
    clean = "".join(secret.split()).replace("=", "").upper()
    clean += "=" * (-len(clean) % 8)
    try:
        return base64.b32decode(clean)
    except Exception as exc:  # binascii.Error
        raise ValueError("TOTP_SECRET is not valid base32") from exc


def _hotp(key: bytes, counter: int) -> str:
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary % 1_000_000).zfill(6)


def check_confirm_code(
    secret: str, code: Any, now: Optional[float] = None
) -> Optional[str]:
    """Return None when the code is valid, otherwise a short reason."""
    global _failures, _locked_until, _last_accepted_step
    now = time.time() if now is None else now
    if now < _locked_until:
        return "confirmation locked after repeated failures; try again later"
    if not secret:
        return (
            "confirmation is required but TOTP_SECRET is not configured on the server"
        )
    text = code.strip() if isinstance(code, str) else ""
    if not (len(text) == 6 and text.isdigit()):
        return "a 6-digit confirmation code is required"
    try:
        key = _base32_key(secret)
    except ValueError:
        return "confirmation is required but TOTP_SECRET is not valid base32"
    step = int(now // 30)
    for s in (step - 1, step, step + 1):
        if hmac.compare_digest(_hotp(key, s), text):
            if s <= _last_accepted_step:
                return "this confirmation code was already used; wait for the next one"
            _last_accepted_step = s
            _failures = 0
            return None
    _failures += 1
    if _failures >= 5:
        _locked_until = now + 5 * 60
        _failures = 0
    return "invalid confirmation code"


def needs_confirmation(name: str, arguments: Optional[Dict[str, Any]]) -> bool:
    """Whether this call needs a code. Tools outside CONFIRM_TOOLS never do.

    send_gmail_message: always (new mail, reply and forward all send).
    manage_event: ordinary create and update never need a code, so the family calendar
    stays easy to use. A code is needed only for delete, or when the call adds attendees
    and does not switch notifications off (send_updates "none"), because that sends
    invitations to people outside Bezzy.
    """
    if name not in CONFIRM_TOOLS:
        return False
    if name == "manage_event":
        args = arguments or {}
        if str(args.get("action", "")).lower() == "delete":
            return True
        has_attendees = bool(args.get("attendees"))
        return has_attendees and str(args.get("send_updates") or "").lower() != "none"
    return True


def add_confirm_to_schema(name: str, schema: Dict[str, Any]) -> Dict[str, Any]:
    """Add the `confirm` field to the JSON schema of a gated tool."""
    props = {
        k: dict(v) if isinstance(v, dict) else v
        for k, v in schema.get("properties", {}).items()
    }
    required = list(schema.get("required", []))
    if name == "manage_event":
        desc = (
            "6-digit confirmation code from Sjoerd's authenticator app. Only needed when "
            "action is delete, or when attendees are added without send_updates 'none'. "
            "Ordinary create and update need no code. Ask Sjoerd; never guess."
        )
    else:
        desc = (
            "6-digit confirmation code from Sjoerd's authenticator app. "
            "Ask Sjoerd; never guess."
        )
        if "confirm" not in required:
            required.append("confirm")
    props["confirm"] = {"type": "string", "description": desc}
    return dict(schema, properties=props, required=required)


# FastMCP's public call_tool starts the middleware chain and then calls call_tool again for
# the real work (the inner call has run_middleware=False). Without this the second pass
# would see no code and refuse a call whose code was already accepted (and used up).
_passed: "contextvars.ContextVar[Optional[str]]" = contextvars.ContextVar(
    "bezzy_confirm_passed", default=None
)


class ConfirmRefused(Exception):
    """Raised when a gated call has no valid confirmation code."""


def gate(name: str, arguments: Optional[Dict[str, Any]]):
    """Check the code once per call. Returns (arguments without `confirm`, reset token).

    The caller must pass the token to release() in a finally block. Raises ConfirmRefused
    with a ready-to-show message when the code is missing or wrong.
    """
    args = dict(arguments or {})
    code = args.pop("confirm", None)
    token = None
    if _passed.get() != name and needs_confirmation(name, args):
        problem = check_confirm_code(TOTP_SECRET, code)
        if problem:
            raise ConfirmRefused("Refused: %s." % problem)
        token = _passed.set(name)
    return args, token


def release(token) -> None:
    if token is not None:
        _passed.reset(token)
