import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import ValidationError

from app.api.findings import get_finding
from app.api.repositories import get_repository
from app.core.dependencies import get_current_user
from app.schemas.repository import RepositoryCreate


class AccessControlTests(unittest.TestCase):
    def test_authentication_requires_a_bearer_token(self):
        with self.assertRaises(HTTPException) as raised:
            get_current_user(None, Mock())

        self.assertEqual(raised.exception.status_code, 401)

    def test_authentication_rejects_invalid_jwt(self):
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="invalid",
        )
        decode = patch(
            "app.core.dependencies.decode_access_token",
            return_value=None,
        )
        with decode:
            with self.assertRaises(HTTPException) as raised:
                get_current_user(credentials, Mock())

        self.assertEqual(raised.exception.status_code, 401)

    def test_repository_lookup_does_not_disclose_unowned_repository(self):
        current_user = SimpleNamespace(id=uuid.uuid4())
        db = Mock()
        db.scalar.return_value = None

        with self.assertRaises(HTTPException) as raised:
            get_repository(uuid.uuid4(), db, current_user)

        self.assertEqual(raised.exception.status_code, 404)

    def test_finding_lookup_does_not_disclose_unowned_finding(self):
        current_user = SimpleNamespace(id=uuid.uuid4())
        db = Mock()
        db.scalar.return_value = None

        with self.assertRaises(HTTPException) as raised:
            get_finding(uuid.uuid4(), db, current_user)

        self.assertEqual(raised.exception.status_code, 404)

    def test_repository_id_input_must_be_a_github_numeric_id(self):
        with self.assertRaises(ValidationError):
            RepositoryCreate(github_repo_id="../user")


if __name__ == "__main__":
    unittest.main()
