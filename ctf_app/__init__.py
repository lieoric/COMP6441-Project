import os
from datetime import timedelta
from pathlib import Path

from flask import Flask


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("CTF_SECRET_KEY", "local-development-secret"),
        DATABASE=os.path.join(app.instance_path, "ctf.sqlite"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    )

    if test_config is None:
        app.config.from_pyfile("config.py", silent=True)
    else:
        app.config.update(test_config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)

    from . import db
    from . import routes

    db.init_app(app)
    app.register_blueprint(routes.bp)

    if not Path(app.config["DATABASE"]).exists():
        with app.app_context():
            db.init_db()

    return app
