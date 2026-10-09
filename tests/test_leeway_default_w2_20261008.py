"""A service refuses a token more than 5 s past its `exp` ITSELF (clean local 401) instead of accepting it
for up to 10 s and forwarding it to auth (auth answered 401 to a token a service had let through).
The @authmesh/sdk 0.4.1 client refreshes 30 s early, so a 5 s server leeway is ample for clock skew."""
from ab0t_auth.config import AuthSettings, create_config


def test_default_leeway_is_5_seconds():
    assert AuthSettings().leeway_seconds == 5


def test_config_built_from_settings_carries_5_seconds():
    cfg = create_config(auth_url="https://auth.example.com")
    assert cfg.leeway_seconds == 5


def test_explicit_leeway_still_wins():
    assert AuthSettings(leeway_seconds=10).leeway_seconds == 10
