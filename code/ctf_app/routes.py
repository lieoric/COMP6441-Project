import sqlite3

from flask import Blueprint, abort, redirect, render_template, request, session, url_for

from .security import (
    get_user,
    plaintext_credentials_match,
    secure_authenticate,
    secure_probe,
    vulnerable_authenticate,
    vulnerable_probe,
)


bp = Blueprint("ctf", __name__)

STAGE_FLAGS = {
    1: "FLAG{syntax_errors_reveal_query_structure}",
    2: "FLAG{authentication_bypassed_with_sqli}",
    3: "FLAG{parameters_keep_data_out_of_code}",
}


def current_mode():
    mode = session.get("mode", "vulnerable")
    if mode not in {"vulnerable", "secure"}:
        mode = "vulnerable"
        session["mode"] = mode
    return mode


def complete_stage(number):
    session[f"stage_{number}_complete"] = True
    session[f"stage_{number}_flag"] = STAGE_FLAGS[number]
    return STAGE_FLAGS[number]


def progress():
    stages = {
        number: bool(session.get(f"stage_{number}_complete", False))
        for number in STAGE_FLAGS
    }
    flags = {
        number: session.get(f"stage_{number}_flag") if stages[number] else None
        for number in STAGE_FLAGS
    }
    return stages, flags


def signed_in_user():
    user_id = session.get("user_id")
    if user_id is None:
        return None
    return get_user(user_id)


@bp.before_app_request
def prepare_session():
    session.permanent = True
    if "mode" not in session:
        session["mode"] = "vulnerable"


@bp.route("/")
def index():
    stages, flags = progress()
    return render_template(
        "index.html",
        mode=current_mode(),
        stages=stages,
        flags=flags,
        user=signed_in_user(),
    )


@bp.route("/mode/<mode>", methods=("GET", "POST"))
def set_mode(mode):
    if mode not in {"vulnerable", "secure"}:
        abort(404)
    session["mode"] = mode
    session.pop("user_id", None)
    session.pop("auth_mode", None)
    return redirect(url_for("ctf.index"))


@bp.route("/challenge/1", methods=("GET", "POST"))
def challenge_one():
    mode = current_mode()
    result = None
    error = None
    success = False
    probe = ""

    if request.method == "POST":
        probe = request.form.get("probe", "")
        if not probe:
            error = "Enter a probe before running the query."
        else:
            try:
                if mode == "vulnerable":
                    vulnerable_probe(probe)
                else:
                    secure_probe(probe)
                result = "The query completed without a SQLite error."
            except sqlite3.Error as database_error:
                result = f"SQLite error: {database_error}"
                if mode == "vulnerable" and "'" in probe:
                    success = True
                    complete_stage(1)
                else:
                    error = "The probe caused an unexpected database error."

    flag = session.get("stage_1_flag")
    return render_template(
        "challenge1.html",
        mode=mode,
        probe=probe,
        result=result,
        error=error,
        success=success,
        flag=flag,
        completed=bool(session.get("stage_1_complete")),
    )


@bp.route("/challenge/2", methods=("GET", "POST"))
def challenge_two():
    if not session.get("stage_1_complete"):
        return redirect(url_for("ctf.challenge_one"))
    mode = current_mode()
    error = None
    result = None
    success = False
    user = None
    username = ""

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if not username or not password:
            error = "Enter both a username and a password."
        else:
            try:
                if mode == "vulnerable":
                    user = vulnerable_authenticate(username, password)
                else:
                    user = secure_authenticate(username, password)
            except sqlite3.Error as database_error:
                error = f"Database error: {database_error}"
            else:
                if user is None:
                    error = "Invalid username or password."
                else:
                    success = True
                    session["user_id"] = user["id"]
                    session["auth_mode"] = mode
                    result = f"Signed in as {user['display_name']}."
                    bypassed = (
                        mode == "vulnerable"
                        and user["role"] == "admin"
                        and not plaintext_credentials_match(username, password)
                    )
                    if bypassed:
                        complete_stage(2)

    flag = session.get("stage_2_flag")
    return render_template(
        "challenge2.html",
        mode=mode,
        username=username,
        error=error,
        result=result,
        success=success,
        flag=flag,
        user=user,
        completed=bool(session.get("stage_2_complete")),
        demo_credentials={"username": "student", "password": "learning123"},
    )


@bp.route("/challenge/3", methods=("GET", "POST"))
def challenge_three():
    if not session.get("stage_2_complete"):
        return redirect(url_for("ctf.challenge_two"))
    mode = current_mode()
    payload = ""
    root_cause = ""
    primary_defense = ""
    vulnerable_result = None
    secure_result = None
    error = None
    success = False

    if request.method == "POST":
        payload = request.form.get("payload", "")
        root_cause = request.form.get("root_cause", "").strip().lower()
        primary_defense = request.form.get("primary_defense", "").strip().lower()
        if not payload:
            error = "Enter one payload to test against both implementations."
        else:
            vulnerable_user = None
            secure_user = None
            try:
                vulnerable_user = vulnerable_authenticate(payload, "comparison-password")
                if vulnerable_user is None:
                    vulnerable_result = "Login rejected."
                else:
                    vulnerable_result = f"Login accepted as {vulnerable_user['username']}."
            except sqlite3.Error as database_error:
                vulnerable_result = f"SQLite error: {database_error}"

            try:
                secure_user = secure_authenticate(payload, "comparison-password")
                if secure_user is None:
                    secure_result = "Login rejected."
                else:
                    secure_result = f"Login accepted as {secure_user['username']}."
            except sqlite3.Error as database_error:
                secure_result = f"SQLite error: {database_error}"

            payload_bypassed = (
                vulnerable_user is not None
                and vulnerable_user["role"] == "admin"
                and secure_user is None
            )
            answers_correct = (
                root_cause == "concatenation"
                and primary_defense == "parameters"
            )
            if payload_bypassed and answers_correct:
                success = True
                complete_stage(3)
            elif not payload_bypassed:
                error = "The payload must bypass the vulnerable login and fail against the secure login."
            else:
                error = "Review the query construction and the primary SQL injection defense."

    flag = session.get("stage_3_flag")
    return render_template(
        "challenge3.html",
        mode=mode,
        payload=payload,
        root_cause=root_cause,
        primary_defense=primary_defense,
        vulnerable_result=vulnerable_result,
        secure_result=secure_result,
        error=error,
        success=success,
        flag=flag,
        completed=bool(session.get("stage_3_complete")),
    )


@bp.route("/profile")
def profile():
    stages, flags = progress()
    return render_template(
        "profile.html",
        mode=current_mode(),
        user=signed_in_user(),
        auth_mode=session.get("auth_mode"),
        stages=stages,
        flags=flags,
    )


@bp.route("/reset-progress", methods=("POST",))
def reset_progress():
    session.clear()
    session["mode"] = "vulnerable"
    return redirect(url_for("ctf.index"))
