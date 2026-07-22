from conftest import finish_stage_one, finish_stage_two


def test_dashboard_starts_in_vulnerable_mode(client):
    response = client.get("/")

    assert response.status_code == 200
    assert b"SQL Authentication Challenge" in response.data
    assert b"0/3 complete" in response.data
    assert b"Vulnerable target" in response.data


def test_stage_routes_are_progressive(client):
    response = client.get("/challenge/2")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/challenge/1")

    finish_stage_one(client)
    response = client.get("/challenge/3")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/challenge/2")


def test_stage_one_detects_vulnerable_query_error(client):
    response = finish_stage_one(client)

    assert response.status_code == 200
    assert b"SQLite error:" in response.data
    assert b"FLAG{syntax_errors_reveal_query_structure}" in response.data
    with client.session_transaction() as session:
        assert session["stage_1_complete"] is True


def test_secure_probe_treats_quote_as_data(client):
    client.get("/mode/secure")
    response = client.post("/challenge/1", data={"probe": "'"})

    assert response.status_code == 200
    assert b"completed without a SQLite error" in response.data
    assert b"FLAG{syntax_errors_reveal_query_structure}" not in response.data
    with client.session_transaction() as session:
        assert "stage_1_complete" not in session


def test_vulnerable_mode_accepts_valid_student_credentials(client):
    finish_stage_one(client)
    response = client.post(
        "/challenge/2",
        data={"username": "student", "password": "learning123"},
    )

    assert response.status_code == 200
    assert b"student" in response.data
    assert b"FLAG{authentication_bypassed_with_sqli}" not in response.data
    with client.session_transaction() as session:
        assert session["auth_mode"] == "vulnerable"
        assert "stage_2_complete" not in session


def test_vulnerable_mode_allows_admin_bypass(client):
    response = finish_stage_two(client)

    assert response.status_code == 200
    assert b"FLAG{authentication_bypassed_with_sqli}" in response.data
    with client.session_transaction() as session:
        assert session["stage_2_complete"] is True
        assert session["auth_mode"] == "vulnerable"

    profile = client.get("/profile")
    assert b"admin" in profile.data
    assert b"FLAG{authentication_bypassed_with_sqli}" in profile.data


def test_secure_mode_accepts_valid_password_and_rejects_injection(client):
    finish_stage_one(client)
    client.get("/mode/secure")

    valid = client.post(
        "/challenge/2",
        data={"username": "student", "password": "learning123"},
    )
    assert valid.status_code == 200
    assert b"student" in valid.data

    rejected = client.post(
        "/challenge/2",
        data={"username": "admin' --", "password": "not-the-password"},
    )
    assert rejected.status_code == 200
    assert b"Invalid username or password" in rejected.data
    assert b"FLAG{authentication_bypassed_with_sqli}" not in rejected.data


def test_stage_three_compares_both_query_paths(client):
    finish_stage_two(client)
    response = client.post(
        "/challenge/3",
        data={
            "payload": "admin' --",
            "root_cause": "concatenation",
            "primary_defense": "parameters",
        },
    )

    assert response.status_code == 200
    assert b"Login accepted as admin" in response.data
    assert b"Login rejected" in response.data
    assert b"FLAG{parameters_keep_data_out_of_code}" in response.data
    with client.session_transaction() as session:
        assert session["stage_3_complete"] is True


def test_stage_three_rejects_wrong_analysis(client):
    finish_stage_two(client)
    response = client.post(
        "/challenge/3",
        data={
            "payload": "admin' --",
            "root_cause": "weak_password",
            "primary_defense": "password_hashing",
        },
    )

    assert b"Review the query construction" in response.data
    assert b"FLAG{parameters_keep_data_out_of_code}" not in response.data


def test_reset_progress_clears_flags_and_mode(client):
    finish_stage_two(client)
    client.get("/mode/secure")

    response = client.post("/reset-progress", follow_redirects=True)

    assert response.status_code == 200
    assert b"0/3 complete" in response.data
    assert b"Vulnerable target" in response.data
    with client.session_transaction() as session:
        assert session["mode"] == "vulnerable"
        assert "stage_1_complete" not in session
        assert "stage_2_complete" not in session


def test_each_stage_has_three_progressive_hints(client):
    stage_one = client.get("/challenge/1")
    assert stage_one.data.count(b"<details>") == 3

    finish_stage_one(client)
    stage_two = client.get("/challenge/2")
    assert stage_two.data.count(b"<details>") == 3

    finish_stage_two(client)
    stage_three = client.get("/challenge/3")
    assert stage_three.data.count(b"<details>") == 3


def test_invalid_mode_is_not_found(client):
    response = client.get("/mode/unknown")

    assert response.status_code == 404
