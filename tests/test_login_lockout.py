import os
import re
import tempfile
import unittest
from unittest.mock import patch


DB_DIR = tempfile.TemporaryDirectory()
os.environ["SECRET_KEY"] = "test-secret-key-for-signal-regression"
os.environ["DATABASE_URL"] = f"sqlite:///{DB_DIR.name}/signal.db"

import app as signal_app
from models import User, db


class LoginLockoutTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        signal_app.app.config.update(TESTING=True)
        with signal_app.app.app_context():
            user = User.query.filter_by(username="admin").first()
            user.password = signal_app.generate_password_hash(
                "ValidPassword123!",
                method="pbkdf2:sha256",
            )
            user.must_change_password = False
            db.session.commit()

    @classmethod
    def tearDownClass(cls):
        with signal_app.app.app_context():
            db.session.remove()
            db.drop_all()
        DB_DIR.cleanup()

    def test_valid_password_is_not_blocked_by_attacker_lockout(self):
        client = signal_app.app.test_client()
        page = client.get("/login")
        match = re.search(
            rb'name="csrf_token"[^>]*value="([^"]+)"',
            page.data,
        )
        self.assertIsNotNone(match)

        with (
            patch.object(
                signal_app.login_guard,
                "is_locked",
                return_value=(True, 240),
            ),
            patch.object(signal_app.login_guard, "reset"),
        ):
            response = client.post(
                "/login",
                data={
                    "csrf_token": match.group(1).decode(),
                    "username": "admin",
                    "password": "ValidPassword123!",
                },
            )

        self.assertEqual(response.status_code, 302)

    def test_new_password_requires_at_least_twelve_characters(self):
        self.assertIsNotNone(
            signal_app._password_policy_error("Short123", "OldPassword123")
        )


if __name__ == "__main__":
    unittest.main()
