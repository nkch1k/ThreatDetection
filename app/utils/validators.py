import ipaddress
from typing import Tuple


def is_valid_ipv4(ip: str) -> bool:
    """
    Check if the provided string is a valid IPv4 address.

    Args:
        ip: IP address string to validate

    Returns:
        bool: True if valid IPv4, False otherwise
    """
    try:
        ipaddress.IPv4Address(ip)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_private_ip(ip: str) -> bool:
    """
    Check if the IP address is a private IP.

    Private IP ranges:
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
    - 127.0.0.0/8 (loopback)

    Args:
        ip: IP address string to check

    Returns:
        bool: True if private IP, False otherwise
    """
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        return ip_obj.is_private or ip_obj.is_loopback
    except (ipaddress.AddressValueError, ValueError):
        return False


def validate_ip_address(ip: str) -> Tuple[bool, str]:
    """
    Comprehensive IP validation with detailed error messages.

    Args:
        ip: IP address string to validate

    Returns:
        Tuple[bool, str]: (is_valid, error_message)
            - (True, "") if valid public IP
            - (False, error_message) if invalid
    """
    if not ip or not isinstance(ip, str):
        return False, "IP address must be a non-empty string"

    ip = ip.strip()

    if not is_valid_ipv4(ip):
        return False, f"Invalid IPv4 address format: {ip}"

    if is_private_ip(ip):
        return False, f"Private IP addresses are not allowed: {ip}"

    return True, ""