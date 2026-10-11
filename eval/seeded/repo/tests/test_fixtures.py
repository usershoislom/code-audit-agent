TEST_USER = {"email": "alice@example.test", "password": "example-password-123"}


def test_placeholder():
    assert TEST_USER["email"].endswith(".test")
