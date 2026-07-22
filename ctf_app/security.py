from werkzeug.security import check_password_hash

from .db import get_db


PUBLIC_USER_FIELDS = "id, username, display_name, role, secret_flag"


def vulnerable_probe(probe):
    query = f"SELECT id FROM users WHERE username = '{probe}'"
    return get_db().execute(query).fetchall()


def secure_probe(probe):
    return get_db().execute(
        "SELECT id FROM users WHERE username = ?",
        (probe,),
    ).fetchall()


def vulnerable_authenticate(username, password):
    query = (
        f"SELECT {PUBLIC_USER_FIELDS} FROM users "
        f"WHERE username = '{username}' AND plaintext_password = '{password}'"
    )
    return get_db().execute(query).fetchone()


def secure_authenticate(username, password):
    user = get_db().execute(
        """
        SELECT id, username, display_name, role, secret_flag, password_hash
        FROM users
        WHERE username = ?
        """,
        (username,),
    ).fetchone()
    if user is None or not check_password_hash(user["password_hash"], password):
        return None
    return user


def plaintext_credentials_match(username, password):
    return (
        get_db()
        .execute(
            "SELECT id FROM users WHERE username = ? AND plaintext_password = ?",
            (username, password),
        )
        .fetchone()
        is not None
    )


def get_user(user_id):
    return get_db().execute(
        f"SELECT {PUBLIC_USER_FIELDS} FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
