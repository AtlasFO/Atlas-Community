"""Tests for dashboard/auth.py — password hashing/verification, session
lifecycle, lockout, password reset tokens, and the RBAC route table.

Every test isolates its own SQLite DB via DEFAULT_DB_PATH (module-level,
computed once at import) rather than the ATLAS_DASHBOARD_DB env var, since
the constant is already frozen by the time these tests import the module.
"""
from __future__ import annotations

import pytest

from dashboard import auth


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "DEFAULT_DB_PATH", tmp_path / "auth.db")
    auth.init_db()


class TestValidation:
    def test_username_length_and_charset(self):
        assert auth.validate_username("ab") is not None  # too short
        assert auth.validate_username("a" * 33) is not None  # too long
        assert auth.validate_username("bad name") is not None  # space
        assert auth.validate_username("good_name-1") is None

    def test_email(self):
        assert auth.validate_email("not-an-email") is not None
        assert auth.validate_email("a@b.com") is None

    def test_password_length(self):
        assert auth.validate_password("short") is not None
        assert auth.validate_password("longenough1") is None

    def test_role(self):
        assert auth.validate_role("superuser") is not None
        assert auth.validate_role("admin") is None


class TestUsers:
    def test_create_and_fetch(self):
        u = auth.create_user("alice", "alice@example.com", "password123", "admin")
        assert u.id > 0
        assert auth.get_user_by_username("alice").id == u.id
        assert auth.get_user_by_email("alice@example.com").id == u.id
        assert auth.get_user_by_id(u.id).username == "alice"

    def test_duplicate_username_rejected(self):
        auth.create_user("bob", "bob@example.com", "password123", "viewer")
        with pytest.raises(auth.AuthError):
            auth.create_user("bob", "other@example.com", "password123", "viewer")

    def test_duplicate_email_rejected(self):
        auth.create_user("carl", "carl@example.com", "password123", "viewer")
        with pytest.raises(auth.AuthError):
            auth.create_user("carl2", "carl@example.com", "password123", "viewer")

    def test_invalid_fields_raise_before_insert(self):
        with pytest.raises(auth.AuthError):
            auth.create_user("x", "not-an-email", "password123", "viewer")
        assert auth.get_user_by_username("x") is None

    def test_has_any_users(self):
        assert auth.has_any_users() is False
        auth.create_user("first", "first@example.com", "password123", "admin")
        assert auth.has_any_users() is True

    def test_list_users_ordered_by_creation(self):
        auth.create_user("user1", "user1@example.com", "password123", "viewer")
        auth.create_user("user2", "user2@example.com", "password123", "viewer")
        names = [u.username for u in auth.list_users()]
        assert names == ["user1", "user2"]

    def test_update_role(self):
        u = auth.create_user("dave", "dave@example.com", "password123", "viewer")
        auth.update_user_role(u.id, "analyst")
        assert auth.get_user_by_id(u.id).role == "analyst"
        with pytest.raises(auth.AuthError):
            auth.update_user_role(u.id, "superuser")

    def test_set_active_revokes_sessions(self):
        u = auth.create_user("eve", "eve@example.com", "password123", "viewer")
        token = auth.create_session(u.id)
        assert auth.get_session_user(token) is not None
        auth.set_user_active(u.id, False)
        assert auth.get_session_user(token) is None
        assert auth.get_user_by_id(u.id).is_active is False

    def test_delete_user(self):
        u = auth.create_user("frank", "frank@example.com", "password123", "viewer")
        auth.delete_user(u.id)
        assert auth.get_user_by_id(u.id) is None

    def test_mutations_on_nonexistent_user_id_raise(self):
        # Regression: UPDATE/DELETE ... WHERE id = ? silently "succeeded"
        # (0 rows affected, no error) for a user_id that doesn't exist —
        # the dashboard reported "success: true" for an action that did
        # nothing. All four admin user-management ops must now report it.
        missing_id = 999999
        with pytest.raises(auth.AuthError):
            auth.update_user_role(missing_id, "analyst")
        with pytest.raises(auth.AuthError):
            auth.set_user_active(missing_id, False)
        with pytest.raises(auth.AuthError):
            auth.set_password(missing_id, "brandnewpassword1")
        with pytest.raises(auth.AuthError):
            auth.delete_user(missing_id)


class TestLogin:
    def test_correct_password(self):
        auth.create_user("gina", "gina@example.com", "correctpassword1", "viewer")
        user = auth.verify_login("gina", "correctpassword1")
        assert user.username == "gina"

    def test_wrong_password(self):
        auth.create_user("hank", "hank@example.com", "correctpassword1", "viewer")
        with pytest.raises(auth.AuthError):
            auth.verify_login("hank", "wrongpassword")

    def test_unknown_username_same_error_as_wrong_password(self):
        # Must not reveal whether the username exists.
        try:
            auth.verify_login("nosuchuser", "whatever12345")
        except auth.AuthError as e1:
            pass
        auth.create_user("ivan", "ivan@example.com", "correctpassword1", "viewer")
        with pytest.raises(auth.AuthError) as e2:
            auth.verify_login("ivan", "wrongpassword")
        # Both are the generic "invalid username or password" message.
        assert "invalid username or password" in str(e2.value)

    def test_inactive_user_cannot_login(self):
        u = auth.create_user("jane", "jane@example.com", "correctpassword1", "viewer")
        auth.set_user_active(u.id, False)
        with pytest.raises(auth.AuthError):
            auth.verify_login("jane", "correctpassword1")

    def test_lockout_after_repeated_failures(self):
        auth.create_user("kim", "kim@example.com", "correctpassword1", "viewer")
        for _ in range(auth.LOCKOUT_MAX_ATTEMPTS):
            with pytest.raises(auth.AuthError):
                auth.verify_login("kim", "wrongpassword")
        assert auth.is_locked_out("kim") is True
        # Even the CORRECT password is refused while locked out.
        with pytest.raises(auth.AuthError, match="too many failed attempts"):
            auth.verify_login("kim", "correctpassword1")

    def test_successful_login_does_not_lock_out(self):
        auth.create_user("liam", "liam@example.com", "correctpassword1", "viewer")
        for _ in range(auth.LOCKOUT_MAX_ATTEMPTS - 1):
            with pytest.raises(auth.AuthError):
                auth.verify_login("liam", "wrongpassword")
        auth.verify_login("liam", "correctpassword1")  # succeeds, resets streak
        assert auth.is_locked_out("liam") is False


class TestSessions:
    def test_create_and_resolve(self):
        u = auth.create_user("mona", "mona@example.com", "password123", "analyst")
        token = auth.create_session(u.id)
        resolved = auth.get_session_user(token)
        assert resolved is not None and resolved.id == u.id

    def test_unknown_token_resolves_to_none(self):
        assert auth.get_session_user("not-a-real-token") is None

    def test_empty_token_resolves_to_none(self):
        assert auth.get_session_user("") is None
        assert auth.get_session_user(None) is None

    def test_revoke(self):
        u = auth.create_user("nina", "nina@example.com", "password123", "viewer")
        token = auth.create_session(u.id)
        auth.revoke_session(token)
        assert auth.get_session_user(token) is None

    def test_revoke_all_for_user(self):
        u = auth.create_user("omar", "omar@example.com", "password123", "viewer")
        t1, t2 = auth.create_session(u.id), auth.create_session(u.id)
        auth.revoke_all_sessions(u.id)
        assert auth.get_session_user(t1) is None
        assert auth.get_session_user(t2) is None


class TestPasswordReset:
    def test_single_use(self):
        u = auth.create_user("paul", "paul@example.com", "password123", "viewer")
        token = auth.create_password_reset_token(u.id)
        assert auth.consume_password_reset_token(token) == u.id
        assert auth.consume_password_reset_token(token) is None

    def test_unknown_token(self):
        assert auth.consume_password_reset_token("bogus") is None

    def test_new_token_invalidates_previous_unused_one(self):
        u = auth.create_user("quinn", "quinn@example.com", "password123", "viewer")
        old = auth.create_password_reset_token(u.id)
        auth.create_password_reset_token(u.id)  # supersedes `old`
        assert auth.consume_password_reset_token(old) is None

    def test_set_password_revokes_sessions(self):
        u = auth.create_user("rosa", "rosa@example.com", "password123", "viewer")
        token = auth.create_session(u.id)
        auth.set_password(u.id, "brandnewpassword1")
        assert auth.get_session_user(token) is None
        assert auth.verify_login("rosa", "brandnewpassword1").id == u.id

    def test_set_password_validates(self):
        u = auth.create_user("sam", "sam@example.com", "password123", "viewer")
        with pytest.raises(auth.AuthError):
            auth.set_password(u.id, "short")


class TestSettings:
    def test_viewer_chat_toggle_default_off(self):
        assert auth.viewer_chat_enabled() is False

    def test_viewer_chat_toggle_roundtrip(self):
        auth.set_viewer_chat_enabled(True)
        assert auth.viewer_chat_enabled() is True
        auth.set_viewer_chat_enabled(False)
        assert auth.viewer_chat_enabled() is False

    def test_get_setting_default(self):
        assert auth.get_setting("nonexistent-key", "fallback") == "fallback"


class TestRBAC:
    def test_role_hierarchy(self):
        assert auth.role_at_least("admin", "viewer") is True
        assert auth.role_at_least("admin", "analyst") is True
        assert auth.role_at_least("admin", "admin") is True
        assert auth.role_at_least("viewer", "analyst") is False
        assert auth.role_at_least("analyst", "admin") is False

    def test_viewer_cannot_reach_analyst_route(self):
        v = auth.create_user("tara", "tara@example.com", "password123", "viewer")
        assert auth.can_access(v, "chat/send") is False
        assert auth.can_access(v, "case_overview") is True

    def test_viewer_cannot_reach_brain(self):
        v = auth.create_user("tobin", "tobin@example.com", "password123", "viewer")
        a = auth.create_user("uma", "uma@example.com", "password123", "analyst")
        for endpoint in ("brain/globe", "brain/knowledge", "brain/search",
                        "brain/learn_status"):
            assert auth.can_access(v, endpoint) is False
            assert auth.can_access(a, endpoint) is True

    def test_analyst_cannot_reach_admin_route(self):
        a = auth.create_user("umar", "umar@example.com", "password123", "analyst")
        assert auth.can_access(a, "config/llm") is False
        assert auth.can_access(a, "chat/send") is True

    def test_admin_reaches_everything_defined(self):
        adm = auth.create_user("vera", "vera@example.com", "password123", "admin")
        for endpoint in auth.ROUTE_MIN_ROLE:
            assert auth.can_access(adm, endpoint) is True

    def test_unknown_route_fails_closed_to_admin(self):
        a = auth.create_user("walt", "walt@example.com", "password123", "analyst")
        adm = auth.create_user("xena", "xena@example.com", "password123", "admin")
        assert auth.can_access(a, "some/未知/route") is False
        assert auth.can_access(adm, "some/未知/route") is True

    def test_no_user_never_has_access(self):
        assert auth.can_access(None, "case_overview") is False

    def test_viewer_chat_toggle_lowers_chat_requirement_for_viewer_only(self):
        v = auth.create_user("yara", "yara@example.com", "password123", "viewer")
        assert auth.can_access(v, "chat/send") is False
        auth.set_viewer_chat_enabled(True)
        try:
            assert auth.can_access(v, "chat/send") is True
            # Unaffected routes are untouched by the toggle.
            assert auth.can_access(v, "config/llm") is False
        finally:
            auth.set_viewer_chat_enabled(False)


class TestSlidingSessions:
    """A session in use keeps living; an idle one ends; none outlives the cap."""

    def _session_row(self, token):
        with auth._connect() as conn:
            return conn.execute(
                "SELECT expires_at, created_at FROM sessions WHERE token = ?",
                (token,)).fetchone()

    def _set(self, token, **cols):
        assignments = ", ".join(f"{k} = ?" for k in cols)
        with auth._write_lock, auth._connect() as conn:
            conn.execute(f"UPDATE sessions SET {assignments} WHERE token = ?",
                         (*cols.values(), token))
            conn.commit()

    def test_use_slides_expiry_forward_up_to_the_cap(self):
        user = auth.create_user("slider", "slider@example.com", "password123", "viewer")
        token = auth.create_session(user.id)
        # Nearly idle-expired: one request pushes the deadline out again.
        self._set(token, expires_at=auth._expires_iso(minutes=5))
        assert auth.get_session_user(token) is not None
        renewed = self._session_row(token)["expires_at"]
        assert renewed > auth._expires_iso(hours=auth.session_idle_hours() - 1)
        # Near the absolute cap: the deadline can only move up to the cap.
        old_login = (auth.datetime.now(auth.timezone.utc)
                     - auth.timedelta(hours=auth.session_max_hours() - 1)).isoformat()
        self._set(token, created_at=old_login)
        assert auth.get_session_user(token) is not None
        capped = self._session_row(token)["expires_at"]
        assert capped <= auth._expires_iso(hours=1, minutes=1)
        assert capped > auth._now_iso()

    def test_idle_past_the_deadline_ends_the_session(self):
        user = auth.create_user("idler", "idler@example.com", "password123", "viewer")
        token = auth.create_session(user.id)
        self._set(token, expires_at=(auth.datetime.now(auth.timezone.utc)
                                     - auth.timedelta(seconds=1)).isoformat())
        assert auth.get_session_user(token) is None


class TestConfigurableSessionLimits:
    """The limits are settings an admin changes, not constants: they are read
    on every request, so a shortened one applies from a session's next
    request on."""

    def test_defaults_when_nothing_is_set(self, monkeypatch):
        monkeypatch.delenv("ATLAS_SESSION_IDLE_HOURS", raising=False)
        monkeypatch.delenv("ATLAS_SESSION_MAX_HOURS", raising=False)
        assert auth.session_idle_hours() == auth.DEFAULT_SESSION_IDLE_HOURS
        assert auth.session_max_hours() == auth.DEFAULT_SESSION_MAX_HOURS
        limits = auth.session_limits()
        assert limits["idle_is_default"] and limits["max_is_default"]

    def test_a_set_value_is_used(self, monkeypatch):
        monkeypatch.setenv("ATLAS_SESSION_IDLE_HOURS", "0.5")
        monkeypatch.setenv("ATLAS_SESSION_MAX_HOURS", "8")
        assert auth.session_idle_hours() == 0.5
        assert auth.session_max_hours() == 8.0

    def test_a_malformed_value_never_breaks_authentication(self, monkeypatch):
        monkeypatch.setenv("ATLAS_SESSION_IDLE_HOURS", "not-a-number")
        assert auth.session_idle_hours() == auth.DEFAULT_SESSION_IDLE_HOURS
        monkeypatch.setenv("ATLAS_SESSION_IDLE_HOURS", "0")
        assert auth.session_idle_hours() == auth.DEFAULT_SESSION_IDLE_HOURS

    def test_the_cap_is_never_shorter_than_the_idle_limit(self, monkeypatch):
        monkeypatch.setenv("ATLAS_SESSION_IDLE_HOURS", "10")
        monkeypatch.setenv("ATLAS_SESSION_MAX_HOURS", "2")
        assert auth.session_max_hours() == 10.0

    def test_a_shortened_idle_limit_expires_a_session_on_the_next_request(
            self, monkeypatch):
        user = auth.create_user("shorty", "shorty@example.com",
                                "password123", "viewer")
        monkeypatch.setenv("ATLAS_SESSION_IDLE_HOURS", "12")
        token = auth.create_session(user.id)
        assert auth.get_session_user(token) is not None
        # The admin cuts the idle limit; the session's last request was now,
        # so it survives — but its deadline follows the new setting.
        monkeypatch.setenv("ATLAS_SESSION_IDLE_HOURS", "0.25")
        assert auth.get_session_user(token) is not None
        with auth._connect() as conn:
            row = conn.execute(
                "SELECT expires_at FROM sessions WHERE token = ?",
                (token,)).fetchone()
        assert row["expires_at"] < auth._expires_iso(hours=1)

    @pytest.mark.parametrize("idle,cap,message", [
        (0, 24, "idle limit"),
        (12, 100000, "absolute limit"),
        (12, 2, "cannot be shorter"),
        ("x", 24, "must be numbers"),
    ])
    def test_refused_settings(self, idle, cap, message, tmp_path, monkeypatch):
        with pytest.raises(ValueError, match=message):
            auth.set_session_limits(idle, cap)

