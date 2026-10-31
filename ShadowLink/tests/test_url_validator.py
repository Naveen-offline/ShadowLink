import pytest

from app.services.url_validator import URLValidationError, validate_and_normalize


def test_basic_normalization():
    p = validate_and_normalize("HTTPS://Example.COM:443/a%20b?x=1#frag")
    assert p.normalized == "https://example.com/a%20b?x=1"
    assert p.hostname == "example.com" and p.registered_domain == "example.com"
    assert p.scheme == "https" and not p.is_ip


def test_scheme_added_when_missing():
    assert validate_and_normalize("example.com/path").scheme == "https"  # documented default


def test_registered_domain_uses_public_suffix_list():
    p = validate_and_normalize("https://login.secure.example.co.uk/x")
    assert p.registered_domain == "example.co.uk" and p.subdomain == "login.secure"


@pytest.mark.parametrize("bad", ["javascript:alert(1)", "data:text/html,hi", "file:///etc/passwd",
                                 "ftp://example.com", "mailto:a@b.com", "gopher://x.com"])
def test_unsupported_schemes_rejected(bad):
    with pytest.raises(URLValidationError):
        validate_and_normalize(bad)


@pytest.mark.parametrize("bad", ["", "   ", None, "http://", "http://exa mple.com", "http://exam\nple.com", "http://a..b.com"])
def test_invalid_inputs_rejected(bad):
    with pytest.raises(URLValidationError):
        validate_and_normalize(bad)


def test_oversized_url_rejected():
    with pytest.raises(URLValidationError):
        validate_and_normalize("http://example.com/" + "a" * 3000, max_length=2048)


@pytest.mark.parametrize("raw", ["http://2130706433/", "http://0x7f000001/", "http://017700000001/", "http://[::1]/",
                                 "http://192.168.1.1:8080/", "http://127.1/", "http://0x7f.0.0.1/", "http://0177.0.0.1/",
                                 "http://169.254.169.254/latest/meta-data", "http://10.0.0.1/", "http://[::ffff:127.0.0.1]/",
                                 "http://0.0.0.0/"])
def test_obfuscated_private_ips_rejected(raw):
    with pytest.raises(URLValidationError):
        validate_and_normalize(raw)


@pytest.mark.parametrize("raw", ["http://134744072/", "http://0x08080808/", "http://01002004010/", "http://8.8.8.8/", "http://8.8.2056/"])
def test_obfuscated_public_ips_normalised(raw):
    p = validate_and_normalize(raw)
    assert p.is_ip and p.hostname == "8.8.8.8"


@pytest.mark.parametrize("raw", ["http://exa mple.com/", "http://example.com/a b"])
def test_whitespace_rejected(raw):
    with pytest.raises(URLValidationError):
        validate_and_normalize(raw)


def test_idn_converted_to_punycode():
    assert validate_and_normalize("http://bücher.example/").hostname == "xn--bcher-kva.example"


def test_userinfo_not_kept_in_normalized_url():
    p = validate_and_normalize("http://paypal.com@evil.example/login")
    assert p.hostname == "evil.example" and "paypal.com@" not in p.normalized


def test_invalid_port():
    with pytest.raises(URLValidationError):
        validate_and_normalize("http://example.com:99999/")


def test_huge_numeric_host_is_not_an_ip_and_is_rejected():
    with pytest.raises(URLValidationError):
        validate_and_normalize("http://99999999999999/")


def test_numeric_looking_domains_are_not_ips():
    p = validate_and_normalize("http://1.2.3.4.example.com/")
    assert not p.is_ip and p.registered_domain == "example.com"
