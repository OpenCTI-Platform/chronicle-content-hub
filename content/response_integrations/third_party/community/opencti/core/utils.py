from __future__ import annotations
import ipaddress
import re

regex_sha512 = r"[0-9a-fA-F]{128}"
regex_sha256 = r"[0-9a-fA-F]{64}"
regex_sha1 = r"[0-9a-fA-F]{40}"
regex_md5 = r"[0-9a-fA-F]{32}"


def get_entity_original_identifier(entity):
    """
    Helper function for getting entity original identifier
    :param entity: entity from which function will get original identifier
    :return: {str} original identifier
    """
    return entity.additional_properties.get("OriginalIdentifier", entity.identifier)


def get_hash_type(value):
    """
    :param value:
    :return:
    """
    if re.match(regex_sha512, value):
        return "sha512"
    elif re.match(regex_sha256, value):
        return "sha256"
    elif re.match(regex_sha1, value):
        return "sha1"
    elif re.match(regex_md5, value):
        return "md5"
    else:
        return None


def is_ipv4(value):
    """Determine whether the provided string is an IPv4 address or valid IPv4 CIDR."""
    try:
        ipaddress.IPv4Address(value)  # Check for individual IP
        return True
    except ipaddress.AddressValueError:
        try:
            ipaddress.IPv4Network(value, strict=False)  # Check for CIDR notation
            return True
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            return False


def parse_csv_list(value: str | None, separator: str = ",") -> list[str]:
    """Parse a comma-separated string into a clean list of non-empty stripped items.

    Used to normalize multi-value action parameters such as Labels.

    :param value: Raw parameter value from the action (may be None or empty).
    :param separator: Separator character, defaults to ",".
    :return: List of trimmed, non-empty strings. Empty list if value is falsy.
    """
    if not value:
        return []
    return [item.strip() for item in value.split(separator) if item and item.strip()]


