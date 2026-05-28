from __future__ import annotations
from pycti import OpenCTIApiClient
from .utils import is_ipv4, get_hash_type
from .OpenCTIParser import OpenCTIParser
from .constants import DEFAULT_LABEL_COLOR


class OpenCTIManagerAPI(object):
    
    def __init__(self, url, token, ssl_verify=True):
        """
        :param url:
        :param token:
        :param ssl_verify:
        """
        self.opencti_api_client = None
        self.url = url
        try:
            self.opencti_api_client = OpenCTIApiClient(
                url=url, 
                token=token,
                ssl_verify=ssl_verify
            )
        except Exception as ex:
            print(ex)
            raise Exception(
                f"Unable to connect to OpenCTI. Please validate your settings. Error: {ex}"
            )
        self.parser = OpenCTIParser()

    def test_connectivity(self):
        """
        :return: dict
        """
        try:
            labels = self.opencti_api_client.label.list()
        except Exception as e:
            raise Exception(
                f"Unable to connect to OpenCTI. Please validate your credentials. Error: {e}"
            )
    
    def search_marking(self, value):
        """
        :param value:
        :return:
        """
        marking_definition = self.opencti_api_client.marking_definition.read(
            filters={
                "mode": "and",
                "filters": [{"key": "definition", "values": [value]}],
                "filterGroups": [],
            }
        )
        return marking_definition

    def search_observable(self, value):
        """
        :param value: str
        :return: dict
        """
        observable = self.opencti_api_client.stix_cyber_observable.read(
            filters={
                "mode": "and",
                "filters": [{"key": "value", "values": [value]}],
                "filterGroups": [],
            }
        )
        if observable is None:
            return None
        else:
            link = self.url+"/dashboard/id/"+observable["id"]
            return self.parser.build_siemplify_observable_object(observable, link)

    def search_indicator(self, value):
        """
        :param value: str
        :return: dict
        """
        indicator = self.opencti_api_client.indicator.read(
            filters={
                "mode": "and",
                "filters": [{"key": "name", "values": [value]}],
                "filterGroups": [],
            }
        )
        if indicator is None:
            return None
        else:
            link = self.url+"/dashboard/id/"+indicator["id"]
            return self.parser.build_siemplify_indicator_object(indicator, link)


    def create_observable(self, obs_value, obs_type, obs_desc=None, obs_labels=[], obs_score=None, marking_str=None, create_indicator=False):
        """
        :param obs_value:
        :param obs_type:
        :param obs_desc:
        :param obs_labels:
        :param obs_score:
        :param marking_str:
        :param create_indicator:
        :return:
        """

        # create label if not already exist
        for label in obs_labels:
            self.create_label(label)

        # resolve marking id
        marking_id = None
        if marking_str:
            marking_definition = self.search_marking(marking_str)
            if marking_definition:
                marking_id = marking_definition.get("standard_id")

        observable_data = None
        if obs_type == "url":
            observable_data = {
                "type": "url",
                "value": obs_value,
            }
        if obs_type == "hostname":
            observable_data = {
                "type": "hostname",
                "value": obs_value,
            }
        if obs_type == "domain":
            observable_data = {
                "type": "domain-name",
                "value": obs_value,
            }
        if obs_type == "email-subject":
            observable_data = {
                "type": "email-message",
                "subject": obs_value,
            }
        if obs_type == "email-addr":
            observable_data = {
                "type": "email-addr",
                "value": obs_value,
            }
        if obs_type == "ip":
            if is_ipv4(obs_value):
                observable_data = {
                    "type": "ipv4-addr",
                    "value": obs_value,
                }
            else:
                observable_data = {
                    "type": "ipv6-addr",
                    "value": obs_value,
                }
        if obs_type == "hash":
            hash_type = get_hash_type(obs_value)
            if hash_type == "md5":
                observable_data = {
                    "type": "file",
                    "hashes": {
                        "md5": obs_value
                    }
                }
            if hash_type == "sha1":
                observable_data = {
                    "type": "file",
                    "hashes": {
                        "sha-1": obs_value
                    }
                }
            if hash_type == "sha256":
                observable_data = {
                    "type": "file",
                    "hashes": {
                        "sha-256": obs_value
                    }
                }
            if hash_type == "sha512":
                observable_data = {
                    "type": "file",
                    "hashes": {
                        "sha-512": obs_value
                    }
                }
        if obs_score:
            obs_score = int(obs_score)

        if obs_desc:
            observable_data["x_opencti_description"] = obs_desc
        if observable_data:
            observable = self.opencti_api_client.stix_cyber_observable.create(
                observableData=observable_data,
                objectMarking=[marking_id],
                x_opencti_score=obs_score,
                createIndicator=create_indicator,
                objectLabel=obs_labels
            )
            return observable
        else:
            return None

    def create_core_relation(self, from_id, to_id, relation):
        """
        :param from_id:
        :param to_id:
        :param relation:
        :return:
        """
        relation = self.opencti_api_client.stix_core_relationship.create(
            fromId=from_id,
            toId=to_id,
            relationship_type=relation
        )
        return relation

    def create_incident(self, name: str, description: str, severity: str, inc_type: str, labels: list, marking_str: str):
        """
        :param name:
        :param description:
        :param severity:
        :param inc_type:
        :param labels:
        :param marking_str:
        :return:
        """
        # create label if not already exist
        for label in labels:
            self.create_label(label)

        # resolve marking id
        marking_id = None
        if marking_str:
            marking_definition = self.search_marking(marking_str)
            if marking_definition:
                marking_id = marking_definition.get("standard_id")

        # create incident
        incident = self.opencti_api_client.incident.create(
            name=name,
            description=description,
            severity=severity,
            incident_type=inc_type,
            objectMarking=[marking_id],
            objectLabel=labels
        )
        return incident

    def create_case_incident(self, name: str, description: str, severity: str, priority: str, inc_type: str, labels: list, marking_str: str, object_refs: list):
        """
        :param name:
        :param description:
        :param severity:
        :param priority:
        :param inc_type:
        :param labels:
        :param marking_str:
        :param object_refs:
        :return:
        """
        # create label if not already exist
        for label in labels:
            self.create_label(label)

        # resolve marking id
        marking_id = None
        if marking_str:
            marking_definition = self.search_marking(marking_str)
            if marking_definition:
                marking_id = marking_definition.get("standard_id")

        # create case incident
        case_incident = self.opencti_api_client.case_incident.create(
            name=name,
            description=description,
            severity=severity,
            priority=priority,
            incident_type=inc_type,
            objectLabel=labels,
            objectMarking=[marking_id],
            objects=object_refs
        )
        return case_incident

    def create_request_for_information(self, name, description, request_type, labels, object_refs):
        """
        :param name:
        :param description:
        :param request_type:
        :param labels:
        :param object_refs
        :return:
        """
        # create label if not already exist
        for label in labels:
            self.create_label(label)

        # create case rfi
        case_rfi = self.opencti_api_client.case_rfi.create(
            name=name,
            description=description,
            information_types=request_type,
            objectLabel=labels,
            objects=object_refs
        )
        return case_rfi

    def create_label(self, value):
        """
        :param value:
        :return:
        """
        self.opencti_api_client.label.read_or_create_unchecked(
            value=value,
            color=DEFAULT_LABEL_COLOR,
        )