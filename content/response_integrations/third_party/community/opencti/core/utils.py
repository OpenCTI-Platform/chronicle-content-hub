from __future__ import annotations

import base64
import ipaddress
import re
from zoneinfo import ZoneInfo
from dateutil import parser as dtparser
from TIPCommon.types import Entity
from TIPCommon.utils import get_entity_original_identifier
from constants import EMAIL_REGEX, EMAIL_ENTITY_TYPE
from SiemplifyDataModel import EntityTypes


regex_sha512 = r"[0-9a-fA-F]{128}"
regex_sha256 = r"[0-9a-fA-F]{64}"
regex_sha1 = r"[0-9a-fA-F]{40}"
regex_md5 = r"[0-9a-fA-F]{32}"


def convert_date_format(date_str):
    """
    :param date_str:
    :return:
    """
    dt = dtparser.parse(date_str)
    dt_utc = dt.astimezone(ZoneInfo("UTC"))
    return dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ")


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

def get_entity_type(entity: Entity) -> str:
    """Helper function to get entity type

    Args:
        entity (Entity): entity to get type from

    Returns:
        str: entity type

    """
    if (
        re.search(EMAIL_REGEX, get_entity_original_identifier(entity))
        and entity.entity_type == EntityTypes.USER
    ):
        return EMAIL_ENTITY_TYPE

    return entity.entity_type

def prepare_hash_identifier(identifier: str) -> str:
    """Normalized the given identifier by converting it to lowercase.

    Args:
        identifier: The input identifier string.

    Returns:
        str: The normalized lowercase identifier.

    """
    return identifier.lower()

def prepare_entity_for_manager(entity: Entity) -> str:
    """Prepare an entity's identifier for the manager based on its type.

    Args:
        entity: The Entity object.

    Results:
        str: A processed entity identifier string.

    """
    identifier = get_entity_original_identifier(entity)

    if entity.entity_type == EntityTypes.FILEHASH:
        return prepare_hash_identifier(identifier)

    return identifier