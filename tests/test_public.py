from engine.ipv6.header import (
    check_count,
    check_hop_by_hop,
    check_type,
    header_batch,
    parse_chain,
)

POLICY = {
    "max_headers": 4,
    "allowed_types": [
        "hop_by_hop",
        "routing",
        "destination",
        "authentication",
        "mobility",
    ],
}


def test_parse_chain_keeps_every_header():
    raw = [
        {"type": "hop_by_hop", "length": 8},
        {"type": "routing", "length": 8},
        {"type": "destination", "length": 8},
    ]
    chain = parse_chain(raw)
    assert [header["type"] for header in chain] == [
        "hop_by_hop",
        "routing",
        "destination",
    ]


def test_chain_length_limit_rejects_oversized_chain():
    chain = [{"type": "destination", "length": 8} for _ in range(4)]
    policy = {"max_headers": 3, "allowed_types": POLICY["allowed_types"]}
    assert check_count(chain, policy) is False


def test_unknown_extension_type_is_rejected():
    header = {"type": "experimental_99", "length": 8}
    assert check_type(header, POLICY["allowed_types"]) is False


def test_hop_by_hop_only_allowed_at_first_position():
    chain = [
        {"type": "destination", "length": 8},
        {"type": "hop_by_hop", "length": 8},
    ]
    assert check_hop_by_hop(chain, POLICY) is False


def test_batch_verifies_packets_independently():
    packets = [
        [
            {"type": "hop_by_hop", "length": 8},
            {"type": "routing", "length": 8},
        ],
        [{"type": "destination", "length": 8}],
    ]
    result = header_batch(packets, POLICY)
    assert [item["count"] for item in result["results"]] == [2, 1]