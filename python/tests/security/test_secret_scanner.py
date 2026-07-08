from khaos.security.secret_scanner import SecretScanner


def test_api_key():
    result = SecretScanner().scan_text("api_key = 'abcd1234abcd1234abcd1234'")

    assert result.has_secrets is True
    assert result.secrets[0].category == "API Key"


def test_aws_key():
    result = SecretScanner().scan_text("AKIA1234567890ABCDEF")

    assert result.has_secrets is True
    assert result.secrets[0].category == "AWS Access Key"


def test_github_token():
    result = SecretScanner().scan_text("token=ghp_1234567890abcdef1234567890abcdef123456")

    assert result.has_secrets is True
    assert result.secrets[0].category == "GitHub Token"


def test_private_key():
    result = SecretScanner().scan_text("-----BEGIN OPENSSH PRIVATE KEY-----")

    assert result.has_secrets is True
    assert result.secrets[0].category == "Private Key"


def test_password():
    result = SecretScanner().scan_text('password="supersecret"')

    assert result.has_secrets is True
    assert result.secrets[0].category == "Password"


def test_database_url():
    result = SecretScanner().scan_text("postgres://user:password@example.com/db")

    assert result.has_secrets is True
    assert result.secrets[0].category == "Database URL with credentials"


def test_jwt():
    token = (
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )

    result = SecretScanner().scan_text(token)

    assert result.has_secrets is True
    assert result.secrets[0].category == "JWT Token"


def test_no_false_positive():
    result = SecretScanner().scan_text("def api_key_name():\n    return 'public example'")

    assert result.has_secrets is False


def test_masking():
    scanner = SecretScanner()

    assert scanner._mask_match("abcd12345678wxyz") == "abcd***wxyz"


def test_max_matches():
    text = "\n".join(f"api_key=abcd1234abcd1234abcd{i:04d}" for i in range(10))

    result = SecretScanner(max_matches=3).scan_text(text)

    assert result.has_secrets is True
    assert len(result.secrets) == 3


def test_empty_text():
    result = SecretScanner().scan_text("")

    assert result.has_secrets is False
    assert result.total_lines_scanned == 0
