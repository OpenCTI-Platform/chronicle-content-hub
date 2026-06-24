from __future__ import annotations

from soar_sdk.SiemplifyUtils import dict_to_flat
from TIPCommon.transformation import add_prefix_to_dict, dict_to_flat

import dataclasses
from dataclasses import field

from .constants import (
    ENRICHMENT_PREFIX,
    GREEN_COLOR,
    RED_COLOR,
    YELLOW_COLOR,
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

        content += f'<br><strong>Score:</strong><span style="color: {status_color};"><strong> {self.score or "N/A"}</strong></span>'
        content += f'<br><strong>Type:</strong> {self.entity_type or "N/A"}'
        content += f'<br><strong>TLP:</strong> {self.object_markings or "N/A"}'
        content += f'<br><strong>Created At:</strong> {self.created_at or "N/A"}'
        content += f'<br><strong>Updated At:</strong> {self.updated_at or "N/A"}'
        content += "<br>"
        content += f'<br><strong>Source: </strong><a href={self.link} target="_blank">{self.link or "N/A"}</a>'
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
        
        content += f'<br><strong>Description:</strong> {self.description or "N/A"}'
        status_color = YELLOW_COLOR
        if self.score:
            if self.score >= 0 and self.score < 10:
                status_color = GREEN_COLOR

            if self.score >= 10 and self.score < 50:
                status_color = YELLOW_COLOR

            if self.score >= 50 and self.score <= 100:
                status_color = RED_COLOR

        content += f'<br><strong>Score:</strong><span style="color: {status_color};"><strong> {self.score or "N/A"}</strong></span>'
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


# ---------------------------------------------------------------------------
#  New enrichment result dataclasses for EnrichEntities2 / EnrichObservable /
#  EnrichIndicator actions.
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class EntityEnrichmentResult2:
    """Lightweight triage result used by *EnrichEntities2*.

    Stores whether the entity was found as an Observable (SCO) and/or an
    Indicator (SDO), together with their respective ``x_opencti_score`` values.
    """

    entity_identifier: str = ""
    entity_type: str = ""

    # Observable (SCO) lookup
    is_observable: bool = False
    observable_score: int | None = None

    # Indicator (SDO) lookup
    is_indicator: bool = False
    indicator_score: int | None = None
    indicator_confidence: int | None = None

    @property
    def effective_score(self) -> int:
        """``max(observable_score, indicator_score)`` — never averaged."""
        scores = [s for s in (self.observable_score, self.indicator_score) if s is not None]
        return max(scores) if scores else 0

    # -- Serialisation helpers ------------------------------------------------

    def to_json(self) -> dict:
        return {
            "entity": self.entity_identifier,
            "entity_type": self.entity_type,
            "is_observable": self.is_observable,
            "observable_score": self.observable_score,
            "is_indicator": self.is_indicator,
            "indicator_score": self.indicator_score,
            "indicator_confidence": self.indicator_confidence,
            "effective_score": self.effective_score,
        }

    def to_enrichment_data(self) -> dict:
        """Flat dict with ``OCTI_`` prefix, injected into ``entity.additional_properties``."""
        data: dict[str, object] = {
            f"{ENRICHMENT_PREFIX}_IsObservable": self.is_observable,
            f"{ENRICHMENT_PREFIX}_IsIndicator": self.is_indicator,
            f"{ENRICHMENT_PREFIX}_EffectiveScore": self.effective_score,
        }
        if self.observable_score is not None:
            data[f"{ENRICHMENT_PREFIX}_ObservableScore"] = self.observable_score
        if self.indicator_score is not None:
            data[f"{ENRICHMENT_PREFIX}_IndicatorScore"] = self.indicator_score
        if self.indicator_confidence is not None:
            data[f"{ENRICHMENT_PREFIX}_IndicatorConfidence"] = self.indicator_confidence
        return data

    def to_insight_html(self) -> str:
        """Short HTML insight for the case wall."""
        score = self.effective_score
        if score >= 50:
            color = RED_COLOR
        elif score >= 10:
            color = YELLOW_COLOR
        else:
            color = GREEN_COLOR

        parts = [
            f'<h3>OpenCTI Triage — <span style="color:{color}">{score}/100</span></h3>',
            f"<strong>Observable (SCO):</strong> {'✅' if self.is_observable else '❌'}",
        ]
        if self.observable_score is not None:
            parts.append(f" — score {self.observable_score}")
        parts.append("<br>")
        parts.append(f"<strong>Indicator (SDO):</strong> {'✅' if self.is_indicator else '❌'}")
        if self.indicator_score is not None:
            parts.append(f" — score {self.indicator_score}")
        if self.indicator_confidence is not None:
            parts.append(f" (confidence {self.indicator_confidence})")
        parts.append("<br>")
        return "".join(parts)


@dataclasses.dataclass
class ObservableEnrichmentResult:
    """Full enrichment result for a single SCO (StixCyberObservable)."""

    entity_identifier: str = ""
    entity_type: str = ""

    found: bool = False
    observable_id: str | None = None
    observable_type: str | None = None
    score: int | None = None
    description: str | None = None
    created_by: str | None = None
    labels: list[str] = field(default_factory=list)
    link: str | None = None

    # All resolved relationships
    relations: list[dict] = field(default_factory=list)

    # -- Factory ---------------------------------------------------------------

    @classmethod
    def from_raw_data(
        cls,
        raw_data: dict,
        identifier: str,
        entity_type: str,
        link: str,
    ) -> "ObservableEnrichmentResult":
        """Build an ``ObservableEnrichmentResult`` from pycti raw response.

        Same mapping pattern as ``OpenCTIParser.build_observable_object``.
        """
        return cls(
            entity_identifier=identifier,
            entity_type=entity_type,
            found=True,
            observable_id=raw_data.get("id"),
            observable_type=raw_data.get("entity_type"),
            score=raw_data.get("x_opencti_score"),
            description=raw_data.get("x_opencti_description"),
            created_by=(raw_data.get("createdBy") or {}).get("name"),
            labels=[lbl.get("value") for lbl in (raw_data.get("objectLabel") or [])],
            link=link,
        )

    # -- Serialisation helpers ------------------------------------------------

    def to_json(self) -> dict:
        return {
            "entity": self.entity_identifier,
            "entity_type": self.entity_type,
            "is_observable": self.found,
            "observable_id": self.observable_id,
            "observable_type": self.observable_type,
            "score": self.score,
            "description": self.description,
            "created_by": self.created_by,
            "labels": self.labels,
            "link": self.link,
            "relations": self.relations,
        }

    def to_enrichment_data(self) -> dict:
        data: dict[str, object] = {
            f"{ENRICHMENT_PREFIX}_is_observable": self.found,
            f"{ENRICHMENT_PREFIX}_observable_id": self.observable_id or "",
            f"{ENRICHMENT_PREFIX}_observable_type": self.observable_type or "",
            f"{ENRICHMENT_PREFIX}_observable_score": self.score if self.score is not None else "",
            f"{ENRICHMENT_PREFIX}_observable_labels": ", ".join(self.labels) if self.labels else "",
            f"{ENRICHMENT_PREFIX}_observable_created_by": self.created_by or "",
        }
        return {k: v for k, v in data.items() if v != ""}

    def to_table(self) -> list[dict]:
        """One row per relationship — suitable for ``construct_csv``."""
        if not self.relations:
            return []
        return [
            {
                "Relation Type": r.get("relation_type", ""),
                "Related Entity Type": r.get("related_entity_type", ""),
                "Related Entity Name": r.get("related_entity_name", ""),
            }
            for r in self.relations
        ]

    def to_insight_html(self) -> str:
        score = self.score if self.score is not None else 0
        if score >= 50:
            color = RED_COLOR
        elif score >= 10:
            color = YELLOW_COLOR
        else:
            color = GREEN_COLOR

        parts = [
            f'<h3>OpenCTI Observable — <span style="color:{color}">{score}/100</span></h3>',
            f"<strong>Type:</strong> {self.observable_type or 'N/A'}<br>",
        ]
        if self.description:
            parts.append(f"<strong>Description:</strong> {self.description}<br>")
        if self.created_by:
            parts.append(f"<strong>Created by:</strong> {self.created_by}<br>")
        if self.labels:
            parts.append(f"<strong>Labels:</strong> {', '.join(self.labels)}<br>")
        if self.link:
            parts.append(f'<strong>Source:</strong> <a href="{self.link}" target="_blank">{self.link}</a><br>')

        # Group relations by type
        if self.relations:
            grouped: dict[str, list[dict]] = {}
            for r in self.relations:
                grouped.setdefault(r.get("relation_type", "unknown"), []).append(r)
            for rel_type, rels in grouped.items():
                parts.append(f"<br><p><strong>{rel_type} ({len(rels)})</strong></p>")
                for r in rels:
                    name = r.get("related_entity_name", "?")
                    etype = r.get("related_entity_type", "")
                    parts.append(f"<p><strong>{name}</strong> — {etype}</p>")
                parts.append("<p>&nbsp;</p>")

        return "".join(parts)


@dataclasses.dataclass
class IndicatorEnrichmentResult:
    """Full enrichment result for a single SDO (Indicator)."""

    entity_identifier: str = ""
    entity_type: str = ""

    found: bool = False
    indicator_id: str | None = None
    indicator_name: str | None = None
    score: int | None = None
    confidence: int | None = None
    valid_from: str | None = None
    valid_until: str | None = None
    pattern: str | None = None
    kill_chain_phases: list[dict] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)
    created_by: str | None = None
    link: str | None = None

    # All resolved relationships
    relations: list[dict] = field(default_factory=list)

    # -- Factory ---------------------------------------------------------------

    @classmethod
    def from_raw_data(
        cls,
        raw_data: dict,
        identifier: str,
        entity_type: str = "",
        link: str = "",
    ) -> "IndicatorEnrichmentResult":
        """Build an ``IndicatorEnrichmentResult`` from pycti raw response.

        Same mapping pattern as ``OpenCTIParser.build_siemplify_indicator_object``.
        """
        return cls(
            entity_identifier=identifier,
            entity_type=entity_type,
            found=True,
            indicator_id=raw_data.get("id"),
            indicator_name=raw_data.get("name"),
            score=raw_data.get("x_opencti_score"),
            confidence=raw_data.get("confidence"),
            valid_from=raw_data.get("valid_from"),
            valid_until=raw_data.get("valid_until"),
            pattern=raw_data.get("pattern"),
            created_by=(raw_data.get("createdBy") or {}).get("name"),
            labels=[lbl.get("value") for lbl in (raw_data.get("objectLabel") or [])],
            kill_chain_phases=[
                {
                    "kill_chain_name": kc.get("kill_chain_name", ""),
                    "phase_name": kc.get("phase_name", ""),
                }
                for kc in (raw_data.get("killChainPhases") or [])
            ],
            link=link,
        )

    # -- Serialisation helpers ------------------------------------------------

    def to_json(self) -> dict:
        return {
            "entity": self.entity_identifier,
            "entity_type": self.entity_type,
            "is_indicator": self.found,
            "indicator_id": self.indicator_id,
            "indicator_name": self.indicator_name,
            "score": self.score,
            "confidence": self.confidence,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "pattern": self.pattern,
            "kill_chain_phases": self.kill_chain_phases,
            "labels": self.labels,
            "created_by": self.created_by,
            "link": self.link,
            "relations": self.relations,
        }

    def to_enrichment_data(self) -> dict:
        data: dict[str, object] = {
            f"{ENRICHMENT_PREFIX}_is_indicator": self.found,
            f"{ENRICHMENT_PREFIX}_indicator_id": self.indicator_id or "",
            f"{ENRICHMENT_PREFIX}_indicator_name": self.indicator_name or "",
            f"{ENRICHMENT_PREFIX}_indicator_score": self.score if self.score is not None else "",
            f"{ENRICHMENT_PREFIX}_indicator_confidence": self.confidence if self.confidence is not None else "",
            f"{ENRICHMENT_PREFIX}_indicator_valid_from": self.valid_from or "",
            f"{ENRICHMENT_PREFIX}_indicator_valid_until": self.valid_until or "",
            f"{ENRICHMENT_PREFIX}_indicator_pattern": self.pattern or "",
            f"{ENRICHMENT_PREFIX}_indicator_labels": ", ".join(self.labels) if self.labels else "",
            f"{ENRICHMENT_PREFIX}_indicator_created_by": self.created_by or "",
        }
        if self.kill_chain_phases:
            phases = [f"{kc.get('kill_chain_name', '')}::{kc.get('phase_name', '')}" for kc in self.kill_chain_phases]
            data[f"{ENRICHMENT_PREFIX}_indicator_kill_chain"] = ", ".join(phases)
        return {k: v for k, v in data.items() if v != ""}

    def to_table(self) -> list[dict]:
        """One row per relationship — suitable for ``construct_csv``."""
        if not self.relations:
            return []
        return [
            {
                "Relation Type": r.get("relation_type", ""),
                "Related Entity Type": r.get("related_entity_type", ""),
                "Related Entity Name": r.get("related_entity_name", ""),
            }
            for r in self.relations
        ]

    def to_insight_html(self) -> str:
        score = self.score if self.score is not None else 0
        if score >= 50:
            color = RED_COLOR
        elif score >= 10:
            color = YELLOW_COLOR
        else:
            color = GREEN_COLOR

        parts = [
            f'<h3>OpenCTI Indicator — <span style="color:{color}">{score}/100</span></h3>',
            f"<strong>Name:</strong> {self.indicator_name or 'N/A'}<br>",
        ]
        if self.confidence is not None:
            parts.append(f"<strong>Confidence:</strong> {self.confidence}<br>")
        if self.valid_from:
            parts.append(f"<strong>Valid from:</strong> {self.valid_from}<br>")
        if self.valid_until:
            parts.append(f"<strong>Valid until:</strong> {self.valid_until}<br>")
        if self.pattern:
            parts.append(f"<strong>Pattern:</strong> <code>{self.pattern}</code><br>")
        if self.labels:
            parts.append(f"<strong>Labels:</strong> {', '.join(self.labels)}<br>")
        if self.created_by:
            parts.append(f"<strong>Created by:</strong> {self.created_by}<br>")
        if self.kill_chain_phases:
            phases = [f"{kc.get('kill_chain_name', '')} → {kc.get('phase_name', '')}" for kc in self.kill_chain_phases]
            parts.append(f"<strong>Kill Chain:</strong> {', '.join(phases)}<br>")
        if self.link:
            parts.append(f'<strong>Source:</strong> <a href="{self.link}" target="_blank">{self.link}</a><br>')

        # Group relations by type
        if self.relations:
            grouped: dict[str, list[dict]] = {}
            for r in self.relations:
                grouped.setdefault(r.get("relation_type", "unknown"), []).append(r)
            for rel_type, rels in grouped.items():
                parts.append(f"<br><p><strong>{rel_type} ({len(rels)})</strong></p>")
                for r in rels:
                    name = r.get("related_entity_name", "?")
                    etype = r.get("related_entity_type", "")
                    parts.append(f"<p><strong>{name}</strong> — {etype}</p>")
                parts.append("<p>&nbsp;</p>")

        return "".join(parts)
