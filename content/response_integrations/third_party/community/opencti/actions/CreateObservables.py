from core.base_action import BaseAction
from core.constants import CREATE_OBSERVABLES_SCRIPT_NAME, EMAIL_ENTITY_TYPE
from core.utils import get_entity_type, parse_csv_list
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import convert_dict_to_json_result_dict
from TIPCommon.extraction import extract_action_param
from TIPCommon.utils import get_entity_original_identifier

SUCCESS_MESSAGE = ""
ERROR_MESSAGE = f"Error executing action {CREATE_OBSERVABLES_SCRIPT_NAME}"

SUPPORTED_ENTITIES = [
    EntityTypes.ADDRESS,
    EntityTypes.FILEHASH,
    EntityTypes.URL,
    EntityTypes.HOSTNAME,
    EntityTypes.DOMAIN,
    EntityTypes.USER,
    EntityTypes.FILENAME,
    EntityTypes.EMAILMESSAGE
]

entity_type_mapper = {
    EntityTypes.HOSTNAME: "hostname",
    EntityTypes.URL: "url",
    EntityTypes.FILEHASH: "hash",
    EntityTypes.FILENAME: "filename",
    EntityTypes.ADDRESS: "ip",
    EntityTypes.DOMAIN: "domain",
    EntityTypes.EMAILMESSAGE: "email-message",
    EMAIL_ENTITY_TYPE: "email-addr",
}


class CreateObservables(BaseAction):
    def __init__(self, script_name: str) -> None:
        super().__init__(script_name)
        self._result_value = True
        self.output_message = SUCCESS_MESSAGE
        self.error_output_message = ERROR_MESSAGE

    def _extract_action_parameters(self) -> None:
        # process action param

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
        # create observables with GraphQL for all supported entities in this run
        successful_entities = []
        failed_entities = []
        self.json_results = {}

        suitable_entities = [
            entity
            for entity in self.soar_action.target_entities
            if entity.entity_type in SUPPORTED_ENTITIES
        ]
        for entity in suitable_entities:
            identifier = get_entity_original_identifier(entity)
            prepared_entity_type = get_entity_type(entity)
            try:
                observable_type = entity_type_mapper[prepared_entity_type]
                result = self.api_client.create_observable(
                    obs_value=identifier,
                    obs_type=observable_type,
                    obs_desc=self.params.description,
                    obs_labels=self.params.labels,
                    obs_score=self.params.score,
                    marking_str=self.params.marking,
                    create_indicator=self.params.create_indicator,
                )
                if result:
                    successful_entities.append(identifier)
                    self.json_results.update({identifier: result})
                else:
                    failed_entities.append(identifier)

            except Exception as err:
                self.logger.exception(
                    f"Failed to create observable for entity '{identifier}'. Error: {err}"
                )
                failed_entities.append(identifier)

        if not suitable_entities:
            self.output_message = "No supported entities were found to create observables."
            self.result_value = False
            self.json_results = {}
            return

        if successful_entities:
            self.json_results = convert_dict_to_json_result_dict(self.json_results)
            self.output_message += (
                f"Successfully created observables for "
                f"entities in {CREATE_OBSERVABLES_SCRIPT_NAME}: \n"
                f" {', '.join(successful_entities)} \n"
            )
            if failed_entities:
                self.output_message += (
                    f"Action wasn't able to create observable for the following "
                    f"entities in {CREATE_OBSERVABLES_SCRIPT_NAME}:"
                    f" \n {', '.join(failed_entities)} \n"
                )
        else:
            self.result_value = False
            self.output_message = (
                "No observables were created for the provided entities"
                f" in {CREATE_OBSERVABLES_SCRIPT_NAME}."
            )


def main() -> None:
    """Entry point for executing the "Create Observables" action script.

    This function initialized the CreateObservables class with
    the predefined script name and triggers its execution.
    """
    CreateObservables(CREATE_OBSERVABLES_SCRIPT_NAME).run()


if __name__ == "__main__":
    main()
