from __future__ import annotations

from soar_sdk.ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from soar_sdk.SiemplifyAction import SiemplifyAction
from soar_sdk.SiemplifyDataModel import EntityTypes
from soar_sdk.SiemplifyUtils import (
    convert_dict_to_json_result_dict,
    output_handler,
)
from TIPCommon import extract_configuration_param, flat_dict_to_csv

from ..core.constants import ENRICH_FILE_HASH_SCRIPT_NAME, INTEGRATION_NAME, OPENCTI_PREFIX
from ..core.OpenCTIManager import OpenCTIManagerAPI
from ..core.utils import get_entity_original_identifier

SUPPORTED_ENTITY_TYPES = [
    EntityTypes.FILEHASH,
    EntityTypes.ADDRESS,
    EntityTypes.URL,
    EntityTypes.USER,
    EntityTypes.DOMAIN,
    EntityTypes.HOSTNAME,
]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ENRICH_FILE_HASH_SCRIPT_NAME
    siemplify.LOGGER.info("================= Main - Param Init =================")

    octi_url = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="URL",
        print_value=True,
    )
    octi_token = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="API Token",
        print_value=False,
    )
    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Verify SSL",
        input_type=bool,
        print_value=True,
    )

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    json_results = {}
    status = EXECUTION_STATE_COMPLETED
    result_value = False
    output_message = ""
    successful_entities = []
    global_is_risky = False

    suitable_entities = [
        entity
        for entity in siemplify.target_entities
        if entity.entity_type == EntityTypes.FILEHASH
    ]

    siemplify.LOGGER.info(
        "Supported entities are: "
        f"{', '.join([get_entity_original_identifier(entity) for entity in suitable_entities])}"
    )

    unenriched_entities = []
    
    for entity in suitable_entities:
        result_list = []
        entity_identifier = get_entity_original_identifier(entity)
        print(entity_identifier)
        try:
            # init manager
            octi_manager = OpenCTIManagerAPI(
                url=octi_url,
                token=octi_token,
                ssl_verify=verify_ssl
            )
            result = octi_manager.search_observable(entity_identifier)
            print("got result")
            print(result)
            if result is None:
                siemplify.LOGGER.info(
                    f"No File details was found for entity: {entity.identifier}"
                )
                unenriched_entities.append(entity)
                continue

            if result:
                result_list.append(result)
                json_results[entity_identifier] = {result}
                entity.is_suspicious = True
            
                # Enrich entity
                print("je suis avant additional_properties update")
                entity.additional_properties.update(result.to_enrichment_data(OPENCTI_PREFIX))
                
                # Add case wall table for entity
                print("je suis avant add_entity_table")
                print(result.to_table())
                print(type(result.to_table()))
                siemplify.result.add_entity_table(
                    entity.identifier, 
                    flat_dict_to_csv(result.to_table()),
                )
                # Fill json with every entity data
                json_results[get_entity_original_identifier(entity)] = result
                
                # json_results[get_entity_original_identifier(entity)].update(
                #  {"execution_status": "success"}
                # )
                create_insight = True
                if result and create_insight:
                    
                    siemplify.add_entity_insight(entity, result.to_insight(), triggered_by=INTEGRATION_NAME)
                    
                    """
                    siemplify.result.add_entity_table(
                        entity_identifier, flat_dict_to_csv(result.to_table())
                    )
                    """
                entity.is_enriched = True
                successful_entities.append(entity)
                siemplify.LOGGER.info(
                    f"Finished processing entity "
                    f"{get_entity_original_identifier(entity)}"
                )
            
            global_is_risky = True

            if successful_entities:
                original_identifiers = [
                    get_entity_original_identifier(entity)
                    for entity in successful_entities
                ]
                identifiers = ", ".join(original_identifiers)
                output_message += (f"Successfully enriched the following entities using "
                                    f"{INTEGRATION_NAME}: \n {identifiers} \n")
                siemplify.update_entities(successful_entities)

            # Main JSON result
            if json_results:
                siemplify.result.add_result_json(
                    {
                        "results": convert_dict_to_json_result_dict(json_results),
                        "is_risky": global_is_risky,
                    }
                )
        except Exception as ex:
            output_message = f"Error executing action “Enrich Entities. Reason: {ex}"
            result_value = False
            status = EXECUTION_STATE_FAILED
            siemplify.LOGGER.error(output_message)
            siemplify.LOGGER.exception(ex)
    
    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        f"\n  status: {status}\n  "
        f"is_success: {result_value}\n  output_message: {output_message}"
    )
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
