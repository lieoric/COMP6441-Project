import pytest

from ctf_app import create_app
from ctf_app.db import init_db


@pytest.fixture
def app(tmp_path):
    database = tmp_path / "test.sqlite"
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-secret",
            "DATABASE": str(database),
        }
    )
    with app.app_context():
        init_db()
    yield app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def runner(app):
    return app.test_cli_runner()


def finish_stage_one(client):
    return client.post("/challenge/1", data={"probe": "'"})


def finish_stage_two(client):
    finish_stage_one(client)
    return client.post(
        "/challenge/2",
        data={"username": "admin' --", "password": "not-the-password"},
    )
