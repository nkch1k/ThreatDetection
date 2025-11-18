import pytest
from app.utils.validators import is_valid_ipv4, is_private_ip, validate_ip_address


class TestIsValidIPv4:
    """Tests for IPv4 format validation"""

    def test_valid_public_ip(self):
        assert is_valid_ipv4("8.8.8.8") is True
        assert is_valid_ipv4("1.1.1.1") is True
        assert is_valid_ipv4("203.0.113.1") is True

    def test_valid_private_ip(self):
        assert is_valid_ipv4("192.168.1.1") is True
        assert is_valid_ipv4("10.0.0.1") is True
        assert is_valid_ipv4("172.16.0.1") is True

    def test_invalid_format(self):
        assert is_valid_ipv4("256.1.1.1") is False
        assert is_valid_ipv4("192.168.1") is False
        assert is_valid_ipv4("192.168.1.1.1") is False
        assert is_valid_ipv4("abc.def.ghi.jkl") is False

    def test_empty_and_invalid_strings(self):
        assert is_valid_ipv4("") is False
        assert is_valid_ipv4("not_an_ip") is False
        assert is_valid_ipv4("192.168.-1.1") is False


class TestIsPrivateIP:
    """Tests for private IP detection"""

    def test_private_class_a(self):
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("10.255.255.254") is True

    def test_private_class_b(self):
        assert is_private_ip("172.16.0.1") is True
        assert is_private_ip("172.31.255.254") is True

    def test_private_class_c(self):
        assert is_private_ip("192.168.0.1") is True
        assert is_private_ip("192.168.255.254") is True

    def test_loopback(self):
        assert is_private_ip("127.0.0.1") is True
        assert is_private_ip("127.0.0.2") is True

    def test_public_ips(self):
        assert is_private_ip("8.8.8.8") is False
        assert is_private_ip("1.1.1.1") is False
        assert is_private_ip("203.0.113.1") is False

    def test_invalid_ip(self):
        assert is_private_ip("invalid") is False
        assert is_private_ip("256.1.1.1") is False


class TestValidateIPAddress:
    """Tests for comprehensive IP validation"""

    def test_valid_public_ip(self):
        is_valid, error = validate_ip_address("8.8.8.8")
        assert is_valid is True
        assert error == ""

    def test_valid_public_ip_with_spaces(self):
        is_valid, error = validate_ip_address("  1.1.1.1  ")
        assert is_valid is True
        assert error == ""

    def test_private_ip_rejection(self):
        is_valid, error = validate_ip_address("192.168.1.1")
        assert is_valid is False
        assert "Private IP" in error

    def test_loopback_rejection(self):
        is_valid, error = validate_ip_address("127.0.0.1")
        assert is_valid is False
        assert "Private IP" in error

    def test_invalid_format(self):
        is_valid, error = validate_ip_address("256.1.1.1")
        assert is_valid is False
        assert "Invalid IPv4" in error

    def test_empty_string(self):
        is_valid, error = validate_ip_address("")
        assert is_valid is False
        assert "non-empty string" in error

    def test_none_value(self):
        is_valid, error = validate_ip_address(None)
        assert is_valid is False
        assert "non-empty string" in error

    def test_malformed_ip(self):
        is_valid, error = validate_ip_address("192.168.1")
        assert is_valid is False
        assert "Invalid IPv4" in error