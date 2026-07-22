from ctf_app.db import get_db


def test_reset_db_command(app, runner):
    with app.app_context():
        get_db().execute("DELETE FROM users")
        get_db().commit()
        assert get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0

    result = runner.invoke(args=["reset-db"])

    assert result.exit_code == 0
    assert "Database reset." in result.output
    with app.app_context():
        rows = get_db().execute(
            "SELECT username, role FROM users ORDER BY id"
        ).fetchall()
        assert [(row["username"], row["role"]) for row in rows] == [
            ("admin", "admin"),
            ("student", "student"),
        ]


def test_session_security_defaults(app):
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert app.config["PERMANENT_SESSION_LIFETIME"].total_seconds() == 1800
