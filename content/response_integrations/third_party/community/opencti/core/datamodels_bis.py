from __future__ import annotations

import dataclasses
from collections import defaultdict
from typing import Any, Optional

from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import convert_string_to_unix_time
from TIPCommon.transformation import add_prefix_to_dict, dict_to_flat
from TIPCommon.types import SingleJson
from core.constants import YELLOW_COLOR, GREEN_COLOR, RED_COLOR, ENRICHMENT_PREFIX

#from constants import (
#    CASE_WALL_LINK,
#    COLLECTIONS_CASE_WALL_LINK,
#    DATA_ENRICHMENT_PREFIX,
#    MAX_ASSOCIATIONS_TO_RETURN_DEFAULT_VALUE,
#    NOTIFICATION_ALLOWED_VERDICTS,
#    PRIVATE_CASE_WALL_LINK,
#    PRIVATE_URL_DATA_TYPE,
#    SEVERITY_GTI_MAPPING,
# )


@dataclasses.dataclass(frozen=True)
class BaseModel:
    raw_data: SingleJson

    def to_json(self) -> SingleJson:
        return dataclasses.asdict(self)

    def to_flat(self) -> dict[str, Any]:
        return dict_to_flat(self.to_json()["raw_data"])

@dataclasses.dataclass(frozen=True)
class BaseObject(BaseModel):
    """Class to create data model for Base Object"""

    @classmethod
    def from_json(cls, raw_data: SingleJson) -> BaseObject:
        """Create a BaseObject object from JSON data.

        Args:
            raw_data (SingleJson): raw data to create BaseObject from

        Returns:
            BaseObject: Base object

        """
        return cls(raw_data=raw_data)

@dataclasses.dataclass(frozen=True)
class Observable(BaseModel):

    def to_table(self):
        return [
            {
                "Description": self.description,
                "Entity Id": self.entity_id,
                "Entity STIX Id": self.entity_stix_id,
                "Created At": self.created_at,
                "Updated At": self.updated_at,
                "Author": self.author,
                "Creators": ",".join(creator for creator in self.creators),
                "Markings": ",".join(marking for marking in self.markings),
                "Labels": ",".join(label for label in self.labels),
                "External References": ",".join(ext_ref for ext_ref in self.external_references),
                "Score": self.score,
                "Link": self.link
            }
        ]

    '''
    def to_json_shorten(
            self,
            entity_type: str | None = None,
            comments: list[Comment] | None = None,
            widget_link: str | None = None,
            cached_html_widget: str | None = None,
            sandboxes_data: dict[str, Sandbox] | None = None,
            mitre_response: Mitre | None = None,
            ai_summary_response=None,
    ) -> SingleJson:
        """Prepare shorten json data from raw data

        Returns:
            SingleJson: SingleJson data

        """
        if comments:
            self.raw_data["comments"] = [comment.raw_data for comment in comments]
        if sandboxes_data:
            self.raw_data["sandboxes_data"] = {
                key: value.raw_data if value else None
                for key, value in sandboxes_data.items()
            }
        if mitre_response:
            if mitre_response.mitre_tactics:
                self.raw_data["related_mitre_tactics"] = mitre_response.mitre_tactics
            if mitre_response.mitre_techniques:
                self.raw_data["related_mitre_techniques"] = (
                    mitre_response.mitre_techniques
                )

        if ai_summary_response:
            self.raw_data["generated_ai_summary"] = ai_summary_response
        if widget_link:
            self.raw_data["widget_link"] = widget_link
        if cached_html_widget:
            self.raw_data["widget_html"] = cached_html_widget
        if entity_type in [EntityTypes.THREATACTOR, EntityTypes.CVE]:
            attributes = self.raw_data.get("attributes", {})
            if entity_type == EntityTypes.THREATACTOR:
                if "aggregations" in attributes:
                    attributes.pop("aggregations")
                attributes["threat_actor_id"] = self.raw_data.get("id", "")
            return attributes

        return self.raw_data
    '''

    def to_insight(self):
        content = f"<br><strong>Entity:</strong> {self.value}<br>"
        content += "<body>"
        status_color = YELLOW_COLOR
        if self.score:
            if self.score >= 0 and self.score < 10:
                status_color = GREEN_COLOR

            if self.score >= 10 and self.score < 50:
                status_color = YELLOW_COLOR

            if self.score >= 50 and self.score <= 100:
                status_color = RED_COLOR

        content += f'<br><strong>Score:</strong><span style="color: {status_color};"><strong> {self.score  or "N/A"}</strong></span>'
        content += f'<br><strong>Type:</strong> {self.entity_type  or "N/A"}'
        content += f'<br><strong>Markings:</strong> {self.markings  or "N/A"}'
        content += f'<br><strong>Created At:</strong> {self.created_at  or "N/A"}'
        content += f'<br><strong>Updated At:</strong> {self.updated_at  or "N/A"}'
        content += "<br>"
        content += f'<br><strong>Source: </strong><a href={self.link} target="_blank">{self.link  or "N/A"}</a>'
        content += "</body>"
        content += "<p>&nbsp;</p>"

        return content

    def get_enrichment_data(self):
        raise NotImplementedError

    def to_enrichment_data(self):
        """Returns cleaned and prefixed enrichment data
        """
        clean_enrichment_data = {
            k: v for k, v in self.get_enrichment_data().items() if v
        }

        #if widget_link:
        #    clean_enrichment_data["widget_link"] = widget_link

        return add_prefix_to_dict(clean_enrichment_data, ENRICHMENT_PREFIX)

    def to_csv(self) -> list[dict]:
        """Converts last analysis results to a list of dictionaries s
           uitable for CSV export.

        Transforms the 'last_analysis_results' dictionary into a list of dictionaries,
        where each dictionary represents an engine's analysis results with keys
        "Name", "Category", "Method", and "Result".

        Returns:
            list: A list of dictionaries, each representing an engine's analysis
                  results.

        """
        engine_csvs = []
        for key, engine in self.last_analysis_results.items():
            engine_csvs.append(
                {
                    "Name": key,
                    "Category": engine.get("category", ""),
                    "Method": engine.get("method", ""),
                    "Result": engine.get("result", ""),
                }
            )

        return engine_csvs


@dataclasses.dataclass(frozen=True)
class URL(Observable):
    """Class to create data model for URL object"""

    entity_type: str
    value: str
    description: str
    entity_id: str
    entity_stix_id: str
    created_at: str
    updated_at: str
    author: str
    creators: list
    markings: list
    labels: list
    external_references: list
    score: int
    link: str

    @classmethod
    def from_json(cls, raw_data: dict, observable_type: str, observable: str, link: str) -> Domain:
        """Create URL object from raw JSON data.

        Args:
            raw_data (dict): raw data of Domain
            observable_type (str): observable type
            observable (str): observable identifier
            link (str): link to the platform entity

        Returns:
            Domain: Domain object

        """
        return cls(
            raw_data=raw_data,
            entity_type=raw_data.get("entity_type", ""),
            value=raw_data.get("value", ""),
            description=raw_data.get("x_opencti_description", ""),
            entity_id=raw_data.get("id", ""),
            entity_stix_id=raw_data.get("standard_id", ""),
            created_at=raw_data.get("created_at", ""),
            updated_at=raw_data.get("updated_at", ""),
            author=(raw_data.get("createdBy") or {}).get("name", ""),
            creators=[m.get("name") for m in raw_data.get("creators", [])],
            markings=[m.get("definition") for m in raw_data.get("objectMarking", [])],
            labels=[m.get("value") for m in raw_data.get("objectLabel", [])],
            external_references=[m.get("url") for m in raw_data.get("externalReferences", [])],
            score=raw_data.get("x_opencti_score", 0),
            link=link
        )

    def get_enrichment_data(self):
        enrichment_data = {
            "id": self.entity_id,
            "stix_id": self.entity_stix_id,
            "description": self.description,
            "score": self.score,
            "labels": ", ".join(self.labels),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "author": self.author,
            "creators": ", ".join(self.creators),
            "markings": ", ".join(self.markings),
            "external_references": ", ".join(self.external_references),
            "link": self.link
        }

        return enrichment_data

@dataclasses.dataclass(frozen=True)
class IP(Observable):
    """Class to create data model for IP object"""

    entity_type: str
    value: str
    description: str
    entity_id: str
    entity_stix_id: str
    created_at: str
    updated_at: str
    author: str
    creators: list
    markings: list
    labels: list
    external_references: list
    score: int
    link: str

    @classmethod
    def from_json(cls, raw_data: dict, observable_type: str, observable: str, link: str) -> Domain:
        """Create IP object from raw JSON data.

        Args:
            raw_data (dict): raw data of Domain
            observable_type (str): ioc type
            observable (str): ioc identifier
            link (str): link to the platform entity

        Returns:
            Domain: IP object

        """
        return cls(
            raw_data=raw_data,
            entity_type=raw_data.get("entity_type", ""),
            value=raw_data.get("value", ""),
            description=raw_data.get("x_opencti_description", ""),
            entity_id=raw_data.get("id", ""),
            entity_stix_id=raw_data.get("standard_id", ""),
            created_at=raw_data.get("created_at", ""),
            updated_at=raw_data.get("updated_at", ""),
            author=(raw_data.get("createdBy") or {}).get("name", ""),
            creators=[m.get("name") for m in raw_data.get("creators", [])],
            markings=[m.get("definition") for m in raw_data.get("objectMarking", [])],
            labels=[m.get("value") for m in raw_data.get("objectLabel", [])],
            external_references=[m.get("url") for m in raw_data.get("externalReferences", [])],
            score=raw_data.get("x_opencti_score", 0),
            link=link
        )

    def get_enrichment_data(self):
        enrichment_data = {
            "id": self.entity_id,
            "stix_id": self.entity_stix_id,
            "description": self.description,
            "score": self.score,
            "labels": ", ".join(self.labels),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "author": self.author,
            "creators": ", ".join(self.creators),
            "markings": ", ".join(self.markings),
            "external_references": ", ".join(self.external_references),
            "link": self.link
        }

        return enrichment_data

@dataclasses.dataclass(frozen=True)
class Domain(Observable):
    """Class to create data model for Domain object"""

    entity_type: str
    value: str
    description: str
    entity_id: str
    entity_stix_id: str
    created_at: str
    updated_at: str
    author: str
    creators: list
    markings: list
    labels: list
    external_references: list
    score: int
    link: str

    @classmethod
    def from_json(cls, raw_data: dict, observable_type: str, observable: str, link: str) -> Domain:
        """Create Domain object from raw JSON data.

        Args:
            raw_data (dict): raw data of Domain
            observable_type (str): ioc type
            observable (str): ioc identifier
            link (str): link to the platform entity

        Returns:
            Domain: Domain object

        """
        return cls(
            raw_data=raw_data,
            entity_type=raw_data.get("entity_type", ""),
            value=raw_data.get("value", ""),
            description=raw_data.get("x_opencti_description", ""),
            entity_id=raw_data.get("id", ""),
            entity_stix_id=raw_data.get("standard_id", ""),
            created_at=raw_data.get("created_at", ""),
            updated_at=raw_data.get("updated_at", ""),
            author=(raw_data.get("createdBy") or {}).get("name", ""),
            creators=[m.get("name") for m in raw_data.get("creators", [])],
            markings=[m.get("definition") for m in raw_data.get("objectMarking", [])],
            labels=[m.get("value") for m in raw_data.get("objectLabel", [])],
            external_references=[m.get("url") for m in raw_data.get("externalReferences", [])],
            score=raw_data.get("x_opencti_score", 0),
            link=link
        )

    def get_enrichment_data(self):
        enrichment_data = {
            "id": self.entity_id,
            "stix_id": self.entity_stix_id,
            "description": self.description,
            "score": self.score,
            "labels": ", ".join(self.labels),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "author": self.author,
            "creators": ", ".join(self.creators),
            "markings": ", ".join(self.markings),
            "external_references": ", ".join(self.external_references),
            "link": self.link
        }

        return enrichment_data
