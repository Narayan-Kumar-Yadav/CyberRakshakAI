from __future__ import annotations

import unittest

from app.observability.redaction import redact_text, redact_url


class RedactionTests(unittest.TestCase):
    def test_redacts_common_secret_shapes(self) -> None:
        value = "password=secret token=abc123456789 bearer qwerty123456789 otp 123456 user@example.com"
        redacted = redact_text(value)

        self.assertNotIn("secret", redacted)
        self.assertNotIn("abc123456789", redacted)
        self.assertNotIn("qwerty123456789", redacted)
        self.assertNotIn("123456", redacted)
        self.assertNotIn("user@example.com", redacted)

    def test_redacts_sensitive_url_query_values(self) -> None:
        redacted = redact_url("https://example.test/path?token=secret-token-value&next=/home")

        self.assertNotIn("secret-token-value", redacted)
        self.assertIn("token=%5BREDACTED%5D", redacted)


if __name__ == "__main__":
    unittest.main()

