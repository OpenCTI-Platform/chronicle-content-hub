from core.base_action import BaseAction
from core.constants import CREATE_INCIDENT_SCRIPT_NAME
from core.utils import parse_csv_list
from TIPCommon.extraction import extract_action_param

SUCCESS_MESSAGE = ""
ERROR_MESSAGE = f"Error executing action {CREATE_INCIDENT_SCRIPT_NAME}"

class CreateIncident(BaseAction):
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
        self.params.severity = extract_action_param(
            self.soar_action,
            param_name="Severity",
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
        # create incident with GraphQL
        result = self.api_client.create_incident(
            name=self.params.name,
            description=self.params.description,
            inc_type=self.params.inc_type,
            severity=self.params.severity,
            labels=self.params.labels,
            marking_str=self.params.marking
        )

        octi_incident_id = result.get("id")

        # Successful execution: the framework will keep execution_state=COMPLETED.
        # On any raised exception, the framework will:
        #   - log the exception
        #   - set result_value=False and execution_state=FAILED
        #   - build output_message from error_output_message + reason
        self.output_message = (
            f"Incident successfully created with identifier {octi_incident_id}"
        )
        self.result_value = octi_incident_id

        # Expose the full OpenCTI response as JsonResult (see Create Incident.yaml
        # > dynamic_results_metadata > result_name: JsonResult).
        # The framework will publish self.json_results via soar_action.result.add_result_json
        # at the end of run() if the dict is non-empty.
        self.json_results = result or {}

def main() -> None:
    """Entry point for executing the "Create Incident" action script.

    This function initialized the CreateIncident class with
    the predefined script name and triggers its execution.
    """
    CreateIncident(CREATE_INCIDENT_SCRIPT_NAME).run()

if __name__ == "__main__":
    main()
