from __future__ import annotations

from core.base_action import BaseAction
from core.constants import ENRICH_OBSERVABLE_SCRIPT_NAME, INTEGRATION_NAME
from core.utils import get_entity_type, prepare_entity_for_manager
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import convert_dict_to_json_result_dict
from TIPCommon.base.action import ExecutionState
from TIPCommon.extraction import extract_action_param
from TIPCommon.transformation import construct_csv
from TIPCommon.utils import get_entity_original_identifier

SUCCESS_MESSAGE = ""
ERROR_MESSAGE = f"Error executing action {ENRICH_OBSERVABLE_SCRIPT_NAME}"

SUPPORTED_ENTITY_TYPES = [
    EntityTypes.ADDRESS,
    EntityTypes.FILEHASH,
    EntityTypes.URL,
    EntityTypes.HOSTNAME,
    EntityTypes.DOMAIN,
]


class EnrichObservable(BaseAction):
    """Full enrichment of an Observable (SCO) in OpenCTI.

    Looks up the entity value as a StixCyberObservable, retrieves its
    metadata (score, labels, description, created_by) and **all**
    relationships (Indicators, other SCOs, TTPs, Malware, etc.).
    """

    def __init__(self, script_name: str) -> None:
        super().__init__(script_name)
        self._result_value = True
        self.output_message = SUCCESS_MESSAGE
        self.error_output_message = ERROR_MESSAGE

    def _extract_action_parameters(self) -> None:
        self.params.threshold = extract_action_param(
            self.soar_action,
            param_name="Threshold",
            default_value=50,
            print_value=True,
            input_type=int,
        )
        self.params.create_insight = extract_action_param(
            self.soar_action,
            param_name="Create Insight",
            default_value=True,
            print_value=True,
            input_type=bool,
        )

    def _perform_action(self, _=None) -> None:
        self.execution_state = ExecutionState.COMPLETED
        failed_entities: list[str] = []
        successful_entities = []
        not_found_entities: list[str] = []
        json_results: dict = {}

        target_entities = self._soar_action.target_entities
        self.logger.info(f"Target entities: {target_entities}")

        suitable_entities = [
            entity
            for entity in target_entities
            if get_entity_type(entity) in SUPPORTED_ENTITY_TYPES
        ]
        self.logger.info(f"Suitable entities: {suitable_entities}")

        for entity in suitable_entities:
            entity_identifier = get_entity_original_identifier(entity)
            try:
                identifier = prepare_entity_for_manager(entity)
                entity_type = entity.entity_type

                self.logger.info(f"Processing entity {entity_identifier} (type={entity_type})")

                result = self.api_client.enrich_observable(
                    identifier=identifier,
                    entity_type=entity_type,
                )

                if not result.found:
                    self.logger.info(f"Observable {entity_identifier} not found in OpenCTI")
                    not_found_entities.append(entity_identifier)
                    continue

                # Populate entity additional properties
                entity.additional_properties.update(result.to_enrichment_data())
                entity.is_enriched = True

                # Risk assessment based on x_opencti_score
                if result.score is not None and result.score >= self.params.threshold:
                    entity.is_suspicious = True

                # Link to OpenCTI
                if result.link:
                    self.soar_action.result.add_entity_link(entity.identifier, result.link)

                # Relations table
                if result.relations:
                    self.soar_action.result.add_data_table(
                        title=f"Observable Relations: {entity.identifier}",
                        data_table=construct_csv(result.to_table()),
                    )

                # Insight
                if self.params.create_insight:
                    self.soar_action.add_entity_insight(
                        entity,
                        result.to_insight_html(),
                        triggered_by=INTEGRATION_NAME,
                    )

                json_results[entity.identifier] = result.to_json()
                successful_entities.append(entity)

            except Exception as err:
                self.logger.error(f"Error processing entity {entity_identifier}: {err}")
                self.logger.exception(err)
                failed_entities.append(entity_identifier)

        # Build JSON result
        self.json_results = convert_dict_to_json_result_dict(json_results)

        # Build output message
        output_parts: list[str] = []
        if successful_entities:
            names = [get_entity_original_identifier(e) for e in successful_entities]
            output_parts.append(
                f"Successfully enriched the following observables using "
                f"{INTEGRATION_NAME}:\n {', '.join(names)}\n"
            )
            self.soar_action.update_entities(successful_entities)

        if not_found_entities:
            output_parts.append(
                f"The following entities were not found as observables in "
                f"{INTEGRATION_NAME}:\n {', '.join(not_found_entities)}\n"
            )

        if failed_entities:
            output_parts.append(
                f"The action wasn't able to enrich the following entities using "
                f"{INTEGRATION_NAME}:\n {', '.join(failed_entities)}\n"
            )

        if not successful_entities:
            self.output_message = "No observables were found in OpenCTI for the provided entities."
            self.result_value = False
        else:
            self.output_message = "\n".join(output_parts)


def main() -> None:
    """Entry point for the *Enrich Observable* action."""
    EnrichObservable(ENRICH_OBSERVABLE_SCRIPT_NAME).run()


if __name__ == "__main__":
    main()

