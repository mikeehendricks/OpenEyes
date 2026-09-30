import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "server"))
sys.path.insert(0, os.path.join(ROOT, "agent"))


@pytest.fixture()
def server(tmp_path):
    """Fresh OpenEyes server app + TestClient + db handle."""
    from fastapi.testclient import TestClient
    from openeyes.app import create_app

    data_dir = tmp_path / "data"
    app = create_app(str(data_dir))
    store = app.state.store
    db = store.db
    client = TestClient(app)
    password = db.get_meta("admin_password")
    yield {"app": app, "client": client, "db": db, "password": password,
           "enrollment_token": db.get_meta("enrollment_token")}
    db.close()


@pytest.fixture()
def admin(server):
    """Server fixture with an authenticated admin session."""
    r = server["client"].post("/api/v1/login",
                              json={"password": server["password"]})
    assert r.status_code == 200, r.text
    return server
