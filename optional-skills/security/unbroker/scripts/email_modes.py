"""Email modes A/B/C helpers + anti-phishing verification-link extraction.

Mode A (default): render a ready-to-send draft to disk; the operator sends it.
Mode B/C: the agent SENDS via a Hermes email mechanism (IMAP/SMTP gateway,
`himalaya`, AgentMail, or Gmail via `google-workspace`) and READS the reply to
resolve the verification link with `extract_verification_link`. Those transports
are driven by the agent through native tools; this module stays network-free so
the hermetic tests pass.
"""
from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

import legal
import paths

_LINK_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
_VERIFY_HINTS = ("opt", "remov", "verif", "confirm", "unsubscrib", "suppress", "delete", "privacy")


def _safe_https_host(url: object) -> str | None:
    """Return URL's normalized host when it is safe metadata or a safe candidate."""
    if not isinstance(url, str) or "\\" in url:
        return None
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return None
    if (parsed.scheme.lower() != "https" or not parsed.netloc or parsed.netloc.endswith(":")
            or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or port not in (None, 443)):
        return None
    return parsed.hostname.lower()


def _verification_hosts(broker: object) -> set[str]:
    """Derive exact trusted verification hosts from existing broker URL metadata."""
    if not isinstance(broker, dict):
        return set()
    optout = broker.get("optout")
    search = broker.get("search")
    optout = optout if isinstance(optout, dict) else {}
    search = search if isinstance(search, dict) else {}
    deletion = optout.get("deletion")
    deletion = deletion if isinstance(deletion, dict) else {}
    hosts = {
        _safe_https_host(optout.get("url")),
        _safe_https_host(search.get("url")),
        _safe_https_host(deletion.get("url")),
    }
    hosts.discard(None)
    return hosts


def render_draft(broker: dict, fields: dict, out_dir: Path | None = None) -> Path:
    """Mode A: write a ready-to-send opt-out email for the operator to send."""
    body = legal.render_optout_email(broker, fields)
    out_dir = out_dir or (paths.data_dir() / "drafts")
    out_dir.mkdir(parents=True, exist_ok=True)
    fp = out_dir / f"{broker.get('id', 'broker')}.txt"
    fp.write_text(body, encoding="utf-8")
    return fp


def render_request_draft(broker: dict, fields: dict, kind: str = "generic",
                         out_dir: Path | None = None) -> Path:
    """Mode A: write a ready-to-send request of a specific KIND.

    kind: generic | ccpa | ccpa_agent | ccpa_indirect | gdpr. Used for indirect-exposure
    (ccpa_indirect) and explicit legal requests, where the generic opt-out wording is wrong.
    The filename is suffixed with the kind so an indirect request does not overwrite an opt-out draft.
    """
    body = legal.render_request(kind, broker, fields)
    out_dir = out_dir or (paths.data_dir() / "drafts")
    out_dir.mkdir(parents=True, exist_ok=True)
    suffix = "" if kind == "generic" else f"-{kind}"
    fp = out_dir / f"{broker.get('id', 'broker')}{suffix}.txt"
    fp.write_text(body, encoding="utf-8")
    return fp


def extract_verification_link(email_body: str, broker: dict | None = None) -> str | None:
    """Return the most likely opt-out/verification link from an email body.

    Anti-phishing: a link is only returned when its exact HTTPS hostname is
    declared by the broker's URL metadata. Hints rank those trusted links only.
    """
    candidates = _LINK_RE.findall(email_body or "")
    trusted_hosts = _verification_hosts(broker)
    if not candidates or not trusted_hosts:
        return None

    best_score, best_link = -1, None
    for link in candidates:
        if _safe_https_host(link) not in trusted_hosts:
            continue
        low = link.lower()
        score = int(any(h in low for h in _VERIFY_HINTS))
        if score > best_score:
            best_score, best_link = score, link
    return best_link
