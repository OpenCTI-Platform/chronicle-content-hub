from datetime import datetime, timezone

from core import utils
from core.base_action import BaseAction
from core.constants import CREATE_INCIDENT_RESPONSE_CASE_SCRIPT_NAME
from core.utils import parse_csv_list
from TIPCommon.extraction import extract_action_param

SUCCESS_MESSAGE = ""
ERROR_MESSAGE = f"Error executing action {CREATE_INCIDENT_RESPONSE_CASE_SCRIPT_NAME}"


class CreateIncidentResponseCase(BaseAction):
    def __init__(self, script_name: str) -> None:
        super().__init__(script_name)
        self._result_value = True
        self.output_message = SUCCESS_MESSAGE
        self.error_output_message = ERROR_MESSAGE

    def _extract_action_parameters(self) -> None:
        # process action param
        self.params.name = extract_action_param(
            self.soar_action,
            param_name="Name",
            print_value=True,
            is_mandatory=True,
        )
        self.params.description = extract_action_param(
            self.soar_action,
            param_name="Description",
            print_value=True,
            is_mandatory=False,
        )
        created = extract_action_param(
            self.soar_action,
            param_name="Created At",
            print_value=True,
            is_mandatory=False,
        )
        if created is None:
            self.params.created = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            self.params.created = utils.convert_date_format(created)

        self.params.severity = extract_action_param(
            self.soar_action,
            param_name="Severity",
            print_value=True,
            is_mandatory=False,
        )
        self.params.priority = extract_action_param(
            self.soar_action,
            param_name="Priority",
            print_value=True,
            is_mandatory=False,
        )
        self.params.inc_type = extract_action_param(
            self.soar_action,
            param_name="Type",
            print_value=True,
            is_mandatory=False,
        )
        self.params.marking = extract_action_param(
            self.soar_action,
            param_name="Marking",
            print_value=True,
            is_mandatory=False,
        )
        labels = extract_action_param(
            self.soar_action,
            param_name="Labels",
            print_value=True,
            is_mandatory=False,
        )
        self.params.labels = parse_csv_list(labels)

    def _perform_action(self, _=None) -> None:
        # create incident response case with GraphQL
        result = self.api_client.create_case_incident(
            name=self.params.name,
            inc_date=self.params.created,
            description=self.params.description,
            inc_type=self.params.inc_type,
            severity=self.params.severity,
            priority=self.params.priority,
            labels=self.params.labels,
            marking_str=self.params.marking,
            object_refs=[],
        )
        octi_incident_case_id = result.get("id")

        # Successful execution: the framework will keep execution_state=COMPLETED.
        # On any raised exception, the framework will:
        #   - log the exception
        #   - set result_value=False and execution_state=FAILED
        #   - build output_message from error_output_message + reason
        self.output_message = (
            f"Incident Response Case successfully created with identifier {octi_incident_case_id}"
        )
        self.result_value = octi_incident_case_id

        # Expose the full OpenCTI response as JsonResult (see Create Incident.yaml
        # > dynamic_results_metadata > result_name: JsonResult).
        # The framework will publish self.json_results via soar_action.result.add_result_json
        # at the end of run() if the dict is non-empty.
        self.json_results = result or {}


def main() -> None:
    """Entry point for executing the "Create Incident Response Case" action script.

    This function initialized the CreateIncidentResponseCase class with
    the predefined script name and triggers its execution.
    """
    CreateIncidentResponseCase(CREATE_INCIDENT_RESPONSE_CASE_SCRIPT_NAME).run()


if __name__ == "__main__":
    main()