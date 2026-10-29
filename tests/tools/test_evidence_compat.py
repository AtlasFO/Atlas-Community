"""The packet tools need a capture in the case: the tshark wrappers like
the tcpdump, ngrep and tcpxtract ones."""


def _profile(*present):
    return {"files": [], "file_count": len(present), "counts": {c: 1 for c in present},
            "absent_classes": [], "present_classes": list(present), "samples": {}}


def test_the_tshark_tools_need_a_capture_like_the_other_packet_tools():
    from tools.evidence_compat import check_tool_against_profile, required_classes_for_tool
    for name in ("net_tshark_export_objects", "net_tshark_conversations", "net_tcpxtract_streams"):
        assert required_classes_for_tool(name) == frozenset({"pcap"})
    assert check_tool_against_profile("net_tshark_export_objects", _profile("pcap", "disk")) is None
    refusal = check_tool_against_profile("net_tshark_export_objects", _profile("disk"))
    assert refusal and refusal["gate"] == "evidence_compat" and refusal["required_any"] == ["pcap"]
