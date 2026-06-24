from __future__ import annotations

INTEGRATION_NAME = "OpenCTI"

# OPENCTI_PREFIX = "OCTI"
DEFAULT_LABEL_COLOR = "#2758d7"

ENRICHMENT_PREFIX = "OCTI"

GREEN_COLOR = "#339966"
RED_COLOR = "#ff0000"
YELLOW_COLOR = "#ffcc00"

# ACTION NAMES
PING_SCRIPT_NAME = f"{INTEGRATION_NAME} - Ping"
CREATE_INCIDENT_SCRIPT_NAME = f"{INTEGRATION_NAME} - Create Incident"
CREATE_INCIDENT_RESPONSE_CASE_SCRIPT_NAME = f"{INTEGRATION_NAME} - Create Incident Response Case"
CREATE_REQUEST_FOR_INFORMATION_SCRIPT_NAME = f"{INTEGRATION_NAME} - Create Request for Information"
CREATE_OBSERVABLE_SCRIPT_NAME = f"{INTEGRATION_NAME} - Create Observable"
CREATE_OBSERVABLES_SCRIPT_NAME = f"{INTEGRATION_NAME} - Create Observables"
ADD_OBJECT_TO_CONTAINER_SCRIPT_NAME = f"{INTEGRATION_NAME} - Add Object to Container"
ENRICH_ENTITIES_SCRIPT_NAME = f"{INTEGRATION_NAME} - Enrich Entities"
ENRICH_INDICATORS_SCRIPT_NAME = f"{INTEGRATION_NAME} - Enrich Indicators"
ENRICH_FILE_HASH_SCRIPT_NAME = f"{INTEGRATION_NAME} - Enrich File Hash"

ENRICH_ENTITIES2_SCRIPT_NAME = f"{INTEGRATION_NAME} - Enrich Entities2"
ENRICH_OBSERVABLE_SCRIPT_NAME = f"{INTEGRATION_NAME} - Enrich Observable"
ENRICH_INDICATOR_SCRIPT_NAME = f"{INTEGRATION_NAME} - Enrich Indicator"

#
EMAIL_REGEX = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
EMAIL_ENTITY_TYPE = 101

IOC_MAPPING = {
    "files": "file",
    "urls": "url",
    "ip_addresses": "ip-address",
    "domains": "domain",
}

# Mapping SOAR EntityType → OpenCTI SCO type used by pycti filters
SOAR_TO_OPENCTI_SCO_TYPE = {
    "ADDRESS": "IPv4-Addr",       # overridden to IPv6-Addr when ":" in identifier
    "HOSTNAME": "Domain-Name",
    "DOMAIN": "Domain-Name",
    "URL": "Url",
    "FILEHASH": "StixFile",
    "USER": "Email-Addr",         # email-based user entities
}
