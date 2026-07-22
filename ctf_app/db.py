import sqlite3

import click
from flask import current_app, g
from flask.cli import with_appcontext
from werkzeug.security import generate_password_hash


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(
            current_app.config["DATABASE"],
            detect_types=sqlite3.PARSE_DECLTYPES,
        )
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    with current_app.open_resource("schema.sql") as schema:
        db.executescript(schema.read().decode("utf8"))
    db.executemany(
        """
        INSERT INTO users
            (username, plaintext_password, password_hash, display_name, role, secret_flag)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        [
            (
                "admin",
                "N3ver-Use-Pl41ntext!",
                generate_password_hash("N3ver-Use-Pl41ntext!"),
                "System Administrator",
                "admin",
                "FLAG{authentication_bypassed_with_sqli}",
            ),
            (
                "student",
                "learning123",
                generate_password_hash("learning123"),
                "Security Student",
                "student",
                None,
            ),
        ],
    )
    db.commit()


@click.command("init-db")
@with_appcontext
def init_db_command():
    init_db()
    click.echo("Database initialized.")


@click.command("reset-db")
@with_appcontext
def reset_db_command():
    init_db()
    click.echo("Database reset.")


def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
    app.cli.add_command(reset_db_command)
