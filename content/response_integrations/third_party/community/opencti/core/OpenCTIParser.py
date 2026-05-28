from __future__ import annotations
from .datamodels import ObservableObject, IndicatorObject


class OpenCTIParser:

    @staticmethod
    def _parse_markings(data):
        """
        :param data:
        :return:
        """
        marking_values = []
        for marking in data.get("objectMarking"):
            marking_values.append(marking.get("definition"))
        return marking_values
    
    @staticmethod
    def _parse_labels(data):
        """
        :param data:
        :return:
        """
        label_values = []
        for label in data.get("objectLabel"):
            label_values.append(label.get("value"))
        return label_values
    
    @staticmethod
    def _parse_external_references(data):
        """
        :param data:
        :return:
        """
        ext_ref_values = []
        for ref in data.get("externalReferences"):
            ext_ref_values.append(ref.get("url"))
        return ext_ref_values

    def build_siemplify_observable_object(self, data, link):
        """
        :param data:
        :param link:
        :return:
        """
        return ObservableObject(
            raw_data=data,
            octi_id=data.get("id"),
            standard_id=data.get("standard_id"),
            entity_type=data.get("entity_type"),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
            creators=data.get("creators"),
            object_markings=self._parse_markings(data),
            labels=self._parse_labels(data),
            external_references=self._parse_external_references(data),
            value=data.get("value"),
            description=data.get("x_opencti_description"),
            score=data.get("x_opencti_score"),
            link=link
        )

    def build_siemplify_indicator_object(self, data, link):
        """
        :param data:
        :param link:
        :return:
        """
        return IndicatorObject(
            raw_data=data,
            octi_id=data.get("id"),
            standard_id=data.get("standard_id"),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
            creators=data.get("creators"),
            created_by=data.get("created_by"),
            object_markings=self._parse_markings(data),
            labels=self._parse_labels(data),
            external_references=self._parse_external_references(data),
            name=data.get("name"),
            description=data.get("x_opencti_description"),
            score=data.get("x_opencti_score"),
            revoked=data.get("revoked"),
            confidence=data.get("confidence"),
            pattern_type=data.get("pattern_type"),
            pattern=data.get("pattern"),
            valid_from=data.get("valid_from"),
            valid_until=data.get("valid_until"),
            detection=data.get("detection"),
            main_observable_type=data.get("main_observable_type"),
            link=link
        )
