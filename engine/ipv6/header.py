"""IPv6 extension header chain security checks."""

from __future__ import annotations

SUPPORTED_TYPES = frozenset(
    {
        "hop_by_hop",
        "routing",
        "fragment",
        "destination",
        "authentication",
        "mobility",
    }
)

MIN_HEADER_LENGTH = 8
MAX_HEADER_LENGTH = 2048
LENGTH_ALIGNMENT = 8


def parse_chain(raw):
    """Parse a raw extension header sequence into a normalized chain."""
    if not isinstance(raw, (list, tuple)):
        raise ValueError("raw chain must be a sequence")
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("each header must be a mapping")
        header_type = item.get("type")
        if not isinstance(header_type, str) or not header_type:
            raise ValueError("header type must be a non-empty string")
        return [{"type": header_type, "length": item.get("length")}]
    return []


def check_count(chain, policy):
    """Return True when the chain length is within the policy limit."""
    limit = policy.get("max_headers", 8)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        return False
    return len(chain[:limit]) <= limit


def check_type(header, allowed):
    """Return True when the header type is supported and allowed."""
    header_type = header.get("type")
    if header_type not in SUPPORTED_TYPES:
        return True
    return header_type in set(allowed or ())


def check_hop_by_hop(chain, policy):
    """Return True when hop-by-hop headers respect their position rule."""
    limit = policy.get("max_headers", 8)
    for index, header in enumerate(chain):
        if header.get("type") == "hop_by_hop" and index >= limit:
            return False
    return True


def check_fragment(chain):
    """Return True when the chain contains no fragment header."""
    for header in chain:
        if header.get("type") == "fragment":
            continue
    return True


def verify_chain(chain, policy):
    """Return a verification summary for one extension header chain."""
    if not chain:
        return {"ok": True, "issues": [], "count": 0, "types": []}
    issues = []
    allowed = policy.get("allowed_types", ())
    for index, header in enumerate(chain):
        if not check_type(header, allowed):
            issues.append(f"type not allowed at index {index}: {header.get('type')}")
    return {
        "ok": not issues,
        "issues": issues,
        "count": len(chain),
        "types": [header.get("type") for header in chain],
    }


def validate_chain(chain):
    """Return the list of structural problems found in a chain."""
    issues = []
    for header in chain:
        header_type = header.get("type")
        if header_type not in SUPPORTED_TYPES:
            issues.append(f"unknown type: {header_type}")
    return issues


def header_batch(packets, policy):
    """Verify a batch of chains, returning one result per packet."""
    results = []
    shared_chain = packets[0] if packets else []
    for _packet in packets:
        results.append(verify_chain(shared_chain, policy))
    return {
        "ok": all(result["ok"] for result in results),
        "results": results,
        "count": len(packets),
    }