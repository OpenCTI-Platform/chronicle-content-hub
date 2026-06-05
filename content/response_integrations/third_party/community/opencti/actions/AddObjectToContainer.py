from core.base_action import BaseAction
from core.constants import ADD_OBJECT_TO_CONTAINER_SCRIPT_NAME
from TIPCommon.extraction import extract_action_param

SUCCESS_MESSAGE = ""
ERROR_MESSAGE = f"Error executing action {ADD_OBJECT_TO_CONTAINER_SCRIPT_NAME}"


class AddObjectToContainer(BaseAction):
    def __init__(self, script_name: str) -> None:
        super().__init__(script_name)
        self._result_value = True
        self.output_message = SUCCESS_MESSAGE
        self.error_output_message = ERROR_MESSAGE

    def _extract_action_parameters(self) -> None:
        # process action param

        self.params.container_type = extract_action_param(
            self.soar_action,
            param_name="Container Type",
            print_value=True,
            is_mandatory=True,
        )

        self.params.container_id = extract_action_param(
            self.soar_action,
            param_name="Container Id",
            print_value=True,
            is_mandatory=True,
        )

        self.params.object_id = extract_action_param(
            self.soar_action,
            param_name="Object Id",
            print_value=True,
            is_mandatory=True,
        )

    def _perform_action(self, _=None) -> None:
        # create observable with GraphQL

        if self.params.container_type == "report":
            result = self.api_client.add_object_to_report(
                report_id=self.params.container_id,
                object_id=self.params.object_id
            )
        elif self.params.container_type == "incident response case":
            result = self.api_client.add_object_to_incident_response_case(
                case_incident_id=self.params.container_id,
                object_id=self.params.object_id
            )
        elif self.params.container_type == "grouping":
            result = self.api_client.add_object_to_grouping(
                grouping_id=self.params.container_id,
                object_id=self.params.object_id
            )
        elif self.params.container_type == "request for information":
            result = self.api_client.add_object_to_request_for_information(
                rfi_id=self.params.container_id,
                object_id=self.params.object_id
            )
        else:
            raise Exception(f"Unsupported container type: {self.params.container_type}")

        # Successful execution: the framework will keep execution_state=COMPLETED.
        # On any raised exception, the framework will:
        #   - log the exception
        #   - set result_value=False and execution_state=FAILED
        #   - build output_message from error_output_message + reason
        self.output_message = (
            f"Object.id {self.params.object_id} successfully added in container {self.params.container_type} with id {self.params.container_id}"
        )


def main() -> None:
    """Entry point for executing the "Add Object To Container" action script.

    This function initialized the AddObjectToContainer class with
    the predefined script name and triggers its execution.
    """
    AddObjectToContainer(ADD_OBJECT_TO_CONTAINER_SCRIPT_NAME).run()


if __name__ == "__main__":
    main()

