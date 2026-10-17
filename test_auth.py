import unittest

from auth_service import hash_password, register_user


class TestRegistration(unittest.TestCase):

    def test_register_user_normalizes_email(self):
        user = register_user("  User@Example.com  ", "StrongPassword123")

        self.assertEqual(user["email"], "user@example.com")
        self.assertIn("password_hash", user)
        self.assertNotIn("password", user)

    def test_password_is_not_stored_as_plain_text(self):
        user = register_user("user@example.com", "StrongPassword123")

        self.assertNotEqual(
            user["password_hash"],
            "StrongPassword123"
        )

    def test_password_hashes_use_different_salts(self):
        first_hash = hash_password("StrongPassword123")
        second_hash = hash_password("StrongPassword123")

        self.assertNotEqual(first_hash, second_hash)

    def test_empty_password_is_rejected(self):
        with self.assertRaises(ValueError):
            register_user("user@example.com", "")

    def test_invalid_email_is_rejected(self):
        with self.assertRaises(ValueError):
            register_user("invalid-email", "StrongPassword123")


if __name__ == "__main__":
    unittest.main()
