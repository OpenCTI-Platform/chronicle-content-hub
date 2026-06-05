from __future__ import annotations
from pycti import OpenCTIApiClient, CaseIncident, CaseRfi, Incident
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

    def search_observable(
        self,
        observable: str,
        observable_type: str,
        raw_response: bool = False
    ):
        """
        :param observable:
        :param observable_type:
        :param raw_response:
        :return:
        """
        search_key = "value"

        # Build filters if value is provided
        if observable_type == "hash":
            hash_type = get_hash_type(observable)
            if hash_type == "md5":
                search_key = "hashes.MD5"
            if hash_type == "sha1":
                search_key = "hashes.SHA-1"
            if hash_type == "sha256":
                search_key = "hashes.SHA-256"
            if hash_type == "sha512":
                search_key = "hashes.SHA-512"

        filters = None
        if observable:
            filters = {
                "mode": "and",
                "filters": [
                    {
                        "key": search_key,
                        "values": [observable],
                        "operator": "eq",
                        "mode": "or",
                    }
                ],
                "filterGroups": [],
            }

        # Search observables
        result = self.opencti_api_client.stix_cyber_observable.read(filters=filters)

        if result is None:
            return None
        elif raw_response:
            return result
        else:
            print("je suis la")
            link = self.url+"/dashboard/id/"+result["id"]
            return self.parser.build_observable_object(raw_data=result, observable_type=observable_type, observable=observable, link=link)

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
        import json
        self.logger.info(json.dumps(indicator))
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
        if obs_type == "email-message":
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
        if obs_type == "filename":
            observable_data = {
                "type": "directory",
                "path": obs_value,
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

    def create_incident(self, name, inc_date, description, severity, inc_type, labels, marking_str):
        """
        :param name:
        :param inc_date:
        :param description:
        :param severity:
        :param inc_type:
        :param labels:
        :param marking_str:
        :return:
        """
        # Generate predictive STIX ID for incident
        stix_id = Incident.generate_id(name, inc_date)

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
            stix_id=stix_id,
            name=name,
            created=inc_date,
            description=description,
            severity=severity,
            incident_type=inc_type,
            objectMarking=[marking_id],
            objectLabel=labels,
            update=True
        )
        return incident

    def create_case_incident(self, name, inc_date, description, severity, priority, inc_type, labels, marking_str, object_refs):
        """
        :param name:
        :param inc_date:
        :param description:
        :param severity:
        :param priority:
        :param inc_type:
        :param labels:
        :param marking_str:
        :param object_refs:
        :return:
        """

        # Generate predictive STIX ID for case incident
        stix_id = CaseIncident.generate_id(name, inc_date)

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
            stix_id=stix_id,
            name=name,
            created=inc_date,
            description=description,
            severity=severity,
            priority=priority,
            incident_type=inc_type,
            objectLabel=labels,
            objectMarking=[marking_id],
            objects=object_refs,
            update=True
        )
        return case_incident

    def create_request_for_information(self, name, rfi_date, description, request_type, labels, object_refs):
        """
        :param name:
        :param description:
        :param request_type:
        :param labels:
        :param object_refs
        :return:
        """

        # Generate predictive STIX ID for case RFI
        stix_id = CaseRfi.generate_id(name, rfi_date)

        # create label if not already exist
        for label in labels:
            self.create_label(label)

        # create case rfi
        case_rfi = self.opencti_api_client.case_rfi.create(
            stix_id=stix_id,
            name=name,
            created=rfi_date,
            description=description,
            information_types=request_type,
            objectLabel=labels,
            objects=object_refs,
            update=True
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

    def add_object_to_report(self, report_id, object_id):
        """
        :param report_id:
        :param object_id:
        :return:
        """
        # Add object to report
        result = self.opencti_api_client.report.add_stix_object_or_stix_relationship(
            id=report_id, stixObjectOrStixRelationshipId=object_id
        )
        return result

    def add_object_to_incident_response_case(self, case_incident_id, object_id):
        """
        :param case_incident_id:
        :param object_id:
        :return:
        """
        # Add object to case incident
        result = self.opencti_api_client.case_incident.add_stix_object_or_stix_relationship(
            id=case_incident_id, stixObjectOrStixRelationshipId=object_id
        )
        return result

    def add_object_to_grouping(self, grouping_id, object_id):
        """
        :param grouping_id:
        :param object_id:
        :return:
        """
        # Add object to grouping
        result = self.opencti_api_client.grouping.add_stix_object_or_stix_relationship(
            id=grouping_id, stixObjectOrStixRelationshipId=object_id
        )
        return result

    def add_object_to_request_for_information(self, rfi_id, object_id):
        """
        :param rfi_id:
        :param object_id:
        :return:
        """
        # Add object to grouping
        result = self.opencti_api_client.case_rfi.add_stix_object_or_stix_relationship(
            id=rfi_id, stixObjectOrStixRelationshipId=object_id
        )
        return result

