from core.base_action import BaseAction
from core.constants import CREATE_OBSERVABLE_SCRIPT_NAME
from core.utils import parse_csv_list
from TIPCommon.extraction import extract_action_param

SUCCESS_MESSAGE = ""
ERROR_MESSAGE = f"Error executing action {CREATE_OBSERVABLE_SCRIPT_NAME}"


class CreateObservable(BaseAction):
    def __init__(self, script_name: str) -> None:
        super().__init__(script_name)
        self._result_value = True
        self.output_message = SUCCESS_MESSAGE
        self.error_output_message = ERROR_MESSAGE

    def _extract_action_parameters(self) -> None:
        # process action param

        self.params.observable_value = extract_action_param(
            self.soar_action,
            param_name="Observable Value",
            print_value=True,
            is_mandatory=True,
        )

        self.params.observable_type = extract_action_param(
            self.soar_action,
            param_name="Observable Type",
            print_value=True,
            is_mandatory=True,
        )

        self.params.description = extract_action_param(
            self.soar_action,
            param_name="Description",
            print_value=True,
            is_mandatory=False,
        )
        self.params.score = extract_action_param(
            self.soar_action,
            param_name="Score",
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
        self.params.create_indicator = extract_action_param(
            self.soar_action,
            param_name="Create Indicator",
            input_type=bool,
            print_value=True,
            is_mandatory=False,

        )
        self.params.labels = parse_csv_list(labels)

    def _perform_action(self, _=None) -> None:
        # create observable with GraphQL

        result = self.api_client.create_observable(
            obs_value=self.params.observable_value,
            obs_type=self.params.observable_type,
            obs_desc=self.params.description,
            obs_labels=self.params.labels,
            obs_score=self.params.score,
            marking_str=self.params.marking,
            create_indicator=self.params.create_indicator
        )

        octi_observable_id = result.get("id")

        import json
        self.logger.info(json.dumps(result, indent=2))

        # Successful execution: the framework will keep execution_state=COMPLETED.
        # On any raised exception, the framework will:
        #   - log the exception
        #   - set result_value=False and execution_state=FAILED
        #   - build output_message from error_output_message + reason
        self.output_message = (
            f"Observable successfully created with identifier {octi_observable_id}"
        )
        self.result_value = octi_observable_id

        # Expose the full OpenCTI response as JsonResult (see Create Incident.yaml
        # > dynamic_results_metadata > result_name: JsonResult).
        # The framework will publish self.json_results via soar_action.result.add_result_json
        # at the end of run() if the dict is non-empty.
        self.json_results = result or {}


def main() -> None:
    """Entry point for executing the "Create Observable" action script.

    This function initialized the CreateObservable class with
    the predefined script name and triggers its execution.
    """
    CreateObservable(CREATE_OBSERVABLE_SCRIPT_NAME).run()


if __name__ == "__main__":
    main()

