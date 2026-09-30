from core.brain import secrets


def test_detects_spec_patterns():
    text = "\n".join([
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "key = AKIAIOSFODNN7EXAMPLE",
        "token: xoxb-12345678-abcdefgh",
        "ghp_abcdefghijklmnop1234",
        "sk-abcdefghijklmnop1234",
        "password=hunter22",
        "api_key=deadbeef",
        "Authorization: Bearer eyJhbGciOi",
        "net use \\\\srv\\share /user:admin P@ssw0rd!",
    ])
    found = {f.pattern for f in secrets.scan_text(text)}
    assert {"private_key", "aws_access_key", "slack_token", "github_token",
            "api_secret_key", "password_assignment", "api_key_assignment",
            "bearer_token", "net_use_password"} <= found


def test_findings_carry_line_not_value():
    findings = secrets.scan_text("a\npassword=supersecret\n")
    assert findings[0].line == 2
    assert "supersecret" not in str(findings)


def test_redact_replaces_value():
    redacted, findings = secrets.redact("cred: password=supersecret end")
    assert "supersecret" not in redacted
    assert "[REDACTED:password_assignment]" in redacted
    assert findings


def test_clean_text_untouched():
    text = "Volatility needs the symbol pack for Win11 24H2 images."
    redacted, findings = secrets.redact(text)
    assert redacted == text
    assert findings == []
