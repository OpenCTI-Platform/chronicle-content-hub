from __future__ import annotations
from TIPCommon.transformation import dict_to_flat, add_prefix_to_dict
from soar_sdk.SiemplifyUtils import flat_dict_to_csv, dict_to_flat

from .constants import (
    YELLOW_COLOR,
    RED_COLOR,
    GREEN_COLOR,
)

class BaseModel:
    """
    Base model for inheritance
    """

    def __init__(self, raw_data):
        self.raw_data = raw_data

    def to_json(self):
        return self.raw_data

    def to_csv(self):
        return dict_to_flat(self.to_json())

    def to_enrichment_data(self, prefix=None):
        data = dict_to_flat(self.raw_data)

class ObservableObject(BaseModel):
    def __init__(
        self,
        raw_data,
        octi_id,
        standard_id,
        creators,
        value,
        description,
        score,
        entity_type,
        object_markings,
        created_at,
        updated_at,
        external_references,
        labels,
        link,
    ):
        super(ObservableObject, self).__init__(raw_data)
        self.octi_id = octi_id
        self.standard_id = standard_id
        self.creators = creators
        self.value = value
        self.description = description
        self.score = score
        self.entity_type = entity_type
        self.object_markings = object_markings
        self.created_at = created_at
        self.updated_at = updated_at
        self.external_references = external_references
        self.labels = labels
        self.link = link

    def to_table(self):
        table_data = {
            "opencti_id": self.octi_id,
            "standard_id": self.standard_id,
            "value": self.value,
            "description": self.description,
            "score": self.score,
            "entity_type": self.entity_type,
            "markings": self.object_markings,
            "creators": self.creators,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "external_references": self.external_references,
            "labels": self.labels,
            "link": self.link,
        }

        return {key: value for key, value in table_data.items() if value}

    def to_enrichment_data(self, prefix=None):
        data = dict_to_flat(self.to_table())
        return add_prefix_to_dict(data, prefix) if prefix else data

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
        content += f'<br><strong>TLP:</strong> {self.object_markings  or "N/A"}'
        content += f'<br><strong>Created At:</strong> {self.created_at  or "N/A"}'
        content += f'<br><strong>Updated At:</strong> {self.updated_at  or "N/A"}'
        content += "<br>"
        content += f'<br><strong>Source: </strong><a href={self.link} target="_blank">{self.link  or "N/A"}</a>'
        content += "</body>"
        content += "<p>&nbsp;</p>"

        return content

class IndicatorObject(BaseModel):
    def __init__(
        self,
        raw_data,
        octi_id,
        standard_id,
        creators,
        name,
        description,
        score,
        object_markings,
        created_at,
        updated_at,
        created_by,
        external_references,
        labels,
        revoked,
        confidence,
        pattern_type,
        pattern,
        valid_from,
        valid_until,
        detection,
        main_observable_type,
        link,
    ):
        super(IndicatorObject, self).__init__(raw_data)
        self.octi_id = octi_id
        self.standard_id = standard_id
        self.creators = creators
        self.name = name
        self.description = description
        self.score = score
        self.object_markings = object_markings
        self.created_at = created_at
        self.updated_at = updated_at
        self.created_by = created_by
        self.external_references = external_references
        self.labels = labels
        self.revoked = revoked
        self.confidence = confidence
        self.pattern_type = pattern_type
        self.pattern = pattern
        self.valid_from = valid_from
        self.valid_until = valid_until
        self.detection = detection
        self.main_observable_type = main_observable_type
        self.link = link

    def to_table(self):
        table_data = {
            "opencti_id": self.octi_id,
            "standard_id": self.standard_id,
            "name": self.name,
            "description": self.description,
            "score": self.score,
            "markings": self.object_markings,
            "creators": self.creators,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "labels": self.labels,
            "revoked": self.revoked,
            "confidence": self.confidence,
            "pattern_type": self.pattern_type,
            "pattern": self.pattern,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "detection": self.detection,
            "main_observable_type": self.main_observable_type,
            "link": self.link,
            "external_references": self.external_references,

        }

        return {key: value for key, value in table_data.items() if value}

    def to_enrichment_data(self, prefix=None):
        data = dict_to_flat(self.to_table())
        return add_prefix_to_dict(data, prefix) if prefix else data

    def to_insight(self):
        content = f"<br><strong>Indicator:</strong> {self.name}<br>"
        content += "<body>"
        
        content += f'<br><strong>Description:</strong> {self.description  or "N/A"}'
        status_color = YELLOW_COLOR
        if self.score:
            if self.score >= 0 and self.score < 10:
                status_color = GREEN_COLOR

            if self.score >= 10 and self.score < 50:
                status_color = YELLOW_COLOR

            if self.score >= 50 and self.score <= 100:
                status_color = RED_COLOR

        content += f'<br><strong>Score:</strong><span style="color: {status_color};"><strong> {self.score  or "N/A"}</strong></span>'
        content += f'<br><strong>Detection:</strong> {self.detection or "N/A"}'
        content += f'<br><strong>Revoked:</strong> {self.revoked or "N/A"}'
        content += f'<br><strong>Valid From:</strong> {self.valid_from or "N/A"}'
        content += f'<br><strong>Valid Until:</strong> {self.valid_until or "N/A"}'
        content += f'<br><strong>Labels:</strong> {", ".join(self.labels) or "N/A"}'
        content += f'<br><strong>Main Observable Type:</strong> {self.main_observable_type or "N/A"}'
        content += f'<br><strong>Pattern Type:</strong> {self.pattern_type or "N/A"}'
        content += f'<br><strong>Pattern:</strong> {self.pattern or "N/A"}'
        content += f'<br><strong>Markings:</strong> {", ".join(self.object_markings) or "N/A"}'
        content += f'<br><strong>Created By:</strong> {self.created_by or "N/A"}'
        content += f'<br><strong>Created At:</strong> {self.created_at or "N/A"}'
        content += f'<br><strong>Updated At:</strong> {self.updated_at or "N/A"}'
        content += "<br>"
        content += f'<br><strong>Source: </strong><a href={self.link} target="_blank">{self.link or "N/A"}</a>'
        content += f'<br><strong>External References: </strong><a href={self.external_references} target="_blank">{self.external_references or "N/A"}</a>'

        content += "</body>"
        content += "<p>&nbsp;</p>"

        return content

