from khaos.security.middleware import SecurityMiddleware


async def test_secret_is_removed_from_string_and_nested_output():
    middleware = SecurityMiddleware()
    secret = "AKIAIOSFODNN7EXAMPLE"
    result, text = await middleware.post_check("read_file", f"key={secret}")
    nested_result, nested = await middleware.post_check("terminal", {"stdout": f"key={secret}"})
    assert result.has_secrets and nested_result.has_secrets
    assert secret not in text
    assert secret not in nested["stdout"]
