"""Auth event extraction from tool output."""
from core.auth_events import extract_auth_events_from_text
from core.auth_ontology import EVENT_AUTH_FAILURE, EVENT_AUTH_SUCCESS

IP = "203.0.113.66"


def test_extracts_success_and_failure():
    text = (
        f'{{"level":"AUDIT_FAILURE","eventID":"4625","ipAddress":"{IP}",'
        f'"timestamp":"2031-02-04T00:00:00Z"}}\n'
        f'{{"level":"AUDIT_SUCCESS","eventID":"4624","ipAddress":"{IP}",'
        f'"logonType":"3","timestamp":"2031-02-04T10:00:00Z"}}'
    )
    events = extract_auth_events_from_text(text, call_id=7, tool="ez")
    classes = {e.event_class for e in events}
    assert EVENT_AUTH_SUCCESS in classes
    assert EVENT_AUTH_FAILURE in classes
    success = [e for e in events if e.event_class == EVENT_AUTH_SUCCESS][0]
    assert success.source_endpoint == IP
    assert success.when == "2031-02-04"
    assert success.auth_factor == "3"
    assert success.source_call_id == 7


def test_bare_eid_without_context_ignored():
    dns = f"05:30:00 IP {IP}.49743 > 192.168.45.1.53: 4624+ A? example.com."
    assert extract_auth_events_from_text(dns) == []


def test_ignores_loopback():
    text = (
        '{"level":"AUDIT_SUCCESS","eventID":"4624","ipAddress":"127.0.0.1",'
        '"logonType":"2","timestamp":"2031-02-04T10:00:00Z"}'
    )
    assert extract_auth_events_from_text(text) == []
