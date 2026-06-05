from TIPCommon.transformation import flat_dict_to_csv, construct_csv

from TIPCommon.base.action import ExecutionState
from core.base_action import BaseAction

from core import utils
from core.constants import ENRICH_ENTITIES_SCRIPT_NAME, INTEGRATION_NAME
from core.utils import parse_csv_list, get_entity_type, prepare_entity_for_manager
from TIPCommon.extraction import extract_action_param
from datetime import datetime, timezone
from SiemplifyDataModel import EntityTypes
from TIPCommon.utils import get_entity_original_identifier
from SiemplifyUtils import convert_dict_to_json_result_dict, unix_now
from core.OpenCTIParser import OpenCTIParser

SUCCESS_MESSAGE = ""
ERROR_MESSAGE = f"Error executing action {ENRICH_ENTITIES_SCRIPT_NAME}"

ENTITY_TYPE_MAP = {
    EntityTypes.FILEHASH: "hash",
    EntityTypes.URL: "url",
    EntityTypes.ADDRESS: "ip",
    EntityTypes.HOSTNAME: "hostname",
    EntityTypes.DOMAIN: "domain-name",
    EntityTypes.USER: "email-addr",
    EntityTypes.FILENAME: "filename",
    EntityTypes.EMAILMESSAGE: "email-message",
}

SUPPORTED_ENTITY_TYPES = [
    EntityTypes.ADDRESS,
    EntityTypes.FILEHASH,
    EntityTypes.URL,
    EntityTypes.HOSTNAME,
    EntityTypes.DOMAIN,
    EntityTypes.CVE,
    EntityTypes.THREATACTOR,
    #EntityTypes.FILENAME,
    #EntityTypes.EMAILMESSAGE
]

RISK_ASSESSMENT_SUPPORTED = [
    EntityTypes.ADDRESS,
    EntityTypes.FILEHASH,
    EntityTypes.URL,
    EntityTypes.HOSTNAME,
    EntityTypes.DOMAIN,
]

class EnrichEntities(BaseAction):

    def __init__(self, script_name: str) -> None:
        super().__init__(script_name)
        self._result_value = True
        self.output_message = SUCCESS_MESSAGE
        self.error_output_message = ERROR_MESSAGE

    def _extract_action_parameters(self) -> None:
    # process action param
        pass

    def _perform_action(self, _=None) -> None:
        # create observables with GraphQL for all supported entities in this run
        self.output_message = SUCCESS_MESSAGE
        self.error_output_message = ERROR_MESSAGE
        self.execution_state = ExecutionState.COMPLETED
        self.failed_entities = []
        self.successful_entities = []
        self.json_results = {}
        self.entities_existing_data = {}
        self.successful_endpoints = []

        target_entities = self._soar_action.target_entities
        self.logger.info(f"target entities: {target_entities}")

        suitable_entities = [
            entity
            for entity in target_entities
            if get_entity_type(entity) in SUPPORTED_ENTITY_TYPES
        ]

        self.logger.info(f"suitable entities: {suitable_entities}")

        for entity in suitable_entities:
            try:
                self._process_entity(entity)
            except Exception as err:
                self.logger.error(f"Error processing entity {entity.identifier}: {err}")
                self.logger.exception(err)
                self.failed_entities.append(entity.identifier)
                self.entities_existing_data[entity.identifier] = {
                    "execution_status": str(err),
                }

        self.logger.info(f"successful_entities: {self.successful_entities}")

        self.logger.info("before")
        self.logger.info(self.json_results)
        self.json_results = convert_dict_to_json_result_dict(self.json_results)
        self.logger.info("after")
        self.logger.info(self.json_results)

        if self.successful_entities:

            original_identifiers = [
                get_entity_original_identifier(entity) for entity in self.successful_entities
            ]
            self.output_message += (
                f"Successfully enriched the "
                f"following entities using  "
                f"{INTEGRATION_NAME}: \n "
                f"{', '.join(original_identifiers)} \n"
            )
            self.soar_action.update_entities(self.successful_entities)

        if self.failed_entities:
            self.output_message += (
                f"The action wasn’t able to enrich the "
                f"following entities using "
                f"{INTEGRATION_NAME}: "
                f"\n {', '.join(self.failed_entities)} \n"
            )

        if not self.successful_entities:
            self.output_message = (
                "The action didn’t enrich any of the provided entities."
            )
            self.result_value = False

        #self._finalize_action(suitable_entities)

    def _process_entity(self, entity):
        """
        :param entity:
        :return:
        """
        self.logger.info(f"-----------------------------------")
        self.logger.info(f"Going to process entity: {entity}")

        entity_identifier = get_entity_original_identifier(entity)
        entity_type = utils.get_entity_type(entity)

        self.logger.info(f"entity identifier: {entity_identifier}")
        self.logger.info(f"entity type: {entity_type}")

        identifier = prepare_entity_for_manager(entity)
        observable_type = ENTITY_TYPE_MAP.get(get_entity_type(entity))
        self.logger.info(f"OpenCTI Observable type: {observable_type}")

        observable_data = self.api_client.search_observable(observable=identifier, observable_type=observable_type)

        #self.logger.info(f"Data from OpenCTI: {observable_data}")
        #import json
        #self.logger.info(f"Data from OpenCTI (JSON: {json.dumps(observable_data.to_json())}")

        #self.entities_existing_data[entity_identifier] = observable_data.to_json_shorten(
        #    get_entity_type(entity)
        #)
        #self.successful_entities.append(entity_identifier)

        self.logger.info(f"OpenCTI Observable data: {observable_data}")

        if observable_data and observable_data.raw_data:

            self.logger.info(f"OK ca marche")

            self.json_results[entity.identifier] = observable_data.to_enrichment_data()

            entity.additional_properties.update(
                observable_data.to_enrichment_data()
            )

            # flag entity as enriched
            entity.is_enriched = True

            # flag entity as suspicious if relevant
            # TODO: make this score threshold configurable
            if (
                entity.entity_type in RISK_ASSESSMENT_SUPPORTED
                and observable_data.score >= 50
            ):
                entity.is_suspicious = True

            self.successful_entities.append(entity)

            self.successful_endpoints.append(
                observable_data.to_insight()
            )

            if observable_data.link:
                self.soar_action.result.add_entity_link(entity.identifier, observable_data.link)

            self.soar_action.result.add_data_table(
                title=f"Report for: {entity.identifier}",
                data_table=construct_csv(observable_data.to_table()),
            )

    '''
    def _finalize_action(self, suitable_entities: list[str]) -> None:
        """Finalizes the action by processing all suitable entities,
        updating their properties, and generating the final output.

        Args:
            suitable_entities: List of entities to finalize.

        """
        json_result = {}
        successful_entities = []
        for entity in suitable_entities:
            entity_identifier = get_entity_original_identifier(entity)
            entity_type = get_entity_type(entity)
            # Comparing identifier name case sensitive.
            entity_existing_data = self.entities_existing_data.get(entity_identifier)
            try:
                self.logger.info(f"entity identifier: {entity_identifier}")
                self.logger.info(f"self.successful_entities: {self.successful_entities}")
                if entity_identifier in self.successful_entities:
                    identifier = prepare_entity_for_manager(entity)
                    if entity_type == EntityTypes.CVE:
                        print("cve")
                        #ioc_data = parser.build_vulnerability_obj(
                        #    {"data": entity_existing_data}
                        #)
                    elif entity_type == EntityTypes.THREATACTOR:
                        print("actor")
                        #ioc_data = parser.build_threat_actor_object(
                        #    entity_existing_data
                        #)
                    else:
                        observable_type = ENTITY_TYPE_MAP.get(entity_type)
                        observable_data = OpenCTIParser.build_observable_object(
                            {"data": entity_existing_data}, observable_type, identifier
                        )
                    comments, widget_link, widget_html = None, None, None

                    #if entity_type not in [EntityTypes.THREATACTOR, EntityTypes.CVE]:
                        #if self.params.retrieve_comments:
                        #    comments = self.api_client.get_comments(
                        #        ioc_type=ioc_type,
                        #        ioc=ioc_data.entity_id,
                        #        limit=self.params.max_comments_to_return,
                        #        show_entity_status=True,
                        #    )
                        #widget_link, widget_html = self.api_client.get_widget(
                        #    entity_identifier, show_entity_status=True
                        #)
                    #should_retrieve_sandbox_analysis: bool = (
                    #        entity_type == EntityTypes.FILEHASH
                    #        and self.params.retrieve_sandbox_analysis
                    #)
                    #sandboxes_data: dict[str, data_models.Sandbox | None] = (
                    #    enricher.get_sandbox_response(
                    #        entity_identifier=entity_identifier,
                    #        sandboxes=self.params.sandbox,
                    #    )
                    #    if should_retrieve_sandbox_analysis
                    #    else {}
                    #)

                    #should_fetch_metre_details: bool = (
                    #        entity_type == EntityTypes.FILEHASH
                    #        and self.params.fetch_mitre_derails
                    #)

                    #mitre_response: data_models.Mitre | None = (
                    #    enricher.get_mitre_response(
                    #        entity_identifier=entity_identifier,
                    #        lowest_mitre_severity=self.params.lowest_mitre_severity,
                    #    )
                    #    if should_fetch_metre_details
                    #    else None
                    #)

                    json_result[entity_identifier] = observable_data.to_json_shorten(
                        entity_type=entity_type,
                        comments=comments,
                        widget_link=widget_link,
                        cached_html_widget=widget_html,
                        #sandboxes_data=sandboxes_data,
                        #mitre_response=mitre_response,
                    )
                    entity.additional_properties.update(
                        observable_data.to_enrichment_data(widget_link)
                    )
                    self.logger.info(f"Risk assessment: {entity_identifier}")
                    is_risky = False
                    if entity_type in RISK_ASSESSMENT_SUPPORTED:
                        score_threshold = self.params.score_threshold
                        #is_risky = assess_risk(
                        #    ioc_data=ioc_data,
                        #    gti_score=self.params.gti_score,
                        #    engine_threshold=self.params.engine_threshold,
                        #    engine_percentage_threshold=percentage_threshold,
                        #    engine_allowlist=self.params.engine_allowlist,
                        #    logger=self.logger,
                        #)
                        is_risky = True
                        self.logger.info(f"is_risky={is_risky}")
                        entity.is_suspicious = is_risky

                    json_result[entity_identifier].update(
                        {
                            "is_risky": is_risky,
                            "execution_status": "success",
                        }
                    )
                    if observable_data.report_link:
                        self.soar_action.result.add_entity_link(
                            entity_identifier, observable_data.report_link
                        )
                    entity.is_enriched = True
                    successful_entities.append(entity)

            except Exception as e:
                json_result[entity_identifier] = {"execution_status": str(e)}
                self.logger.error(
                    f"An error occurred  {entity}: {str(e)}"
                )
                self.logger.exception(e)
                self.failed_entities.append(entity_identifier)

        self.json_results = convert_dict_to_json_result_dict(json_result)

        if successful_entities:
            original_identifiers = [
                get_entity_original_identifier(entity) for entity in successful_entities
            ]
            self.output_message += (
                f"Successfully enriched the "
                f"following entities using  "
                f"{INTEGRATION_NAME}: \n "
                f"{', '.join(original_identifiers)} \n"
            )
            self.soar_action.update_entities(successful_entities)

        if self.failed_entities:
            self.output_message += (
                f"The action wasn’t able to enrich the "
                f"following entities using "
                f"{INTEGRATION_NAME}: "
                f"\n {', '.join(self.failed_entities)} \n"
            )

        if not self.successful_entities:
            self.output_message = (
                "The action didn’t enrich any of the provided entities."
            )
            self.result_value = False
        '''

def main() -> None:
    """Entry point for executing the "Enrich Entities" action script.

    This function initialized the EnrichEntities class with
    the predefined script name and triggers its execution.
    """
    EnrichEntities(ENRICH_ENTITIES_SCRIPT_NAME).run()

if __name__ == "__main__":
    main()
