from __future__ import annotations
from soar_sdk.SiemplifyAction import SiemplifyAction
from soar_sdk.SiemplifyUtils import unix_now, convert_unixtime_to_datetime, output_handler
from soar_sdk.ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED,EXECUTION_STATE_TIMEDOUT
from ..core.constants import INTEGRATION_NAME, ENRICH_INDICATORS_SCRIPT_NAME, OPENCTI_PREFIX
from ..core.utils import get_entity_original_identifier
from soar_sdk.SiemplifyDataModel import EntityTypes
from ..core.OpenCTIManager import OpenCTIManagerAPI
from soar_sdk.SiemplifyUtils import (
    add_prefix_to_dict_keys,
    convert_dict_to_json_result_dict,
    dict_to_flat,
    output_handler,
)
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv, flat_dict_to_csv


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
    siemplify.script_name = ENRICH_INDICATORS_SCRIPT_NAME
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
        if entity.entity_type in SUPPORTED_ENTITY_TYPES
    ]
    siemplify.LOGGER.info(
        "Supported entities are: "
        f"{', '.join([get_entity_original_identifier(entity) for entity in suitable_entities])}"
    )
    
    for entity in suitable_entities:
        result_list = []
        print(entity)
        print(entity.entity_type)
        entity_identifier = get_entity_original_identifier(entity)
        print(entity_identifier)
        try:
            # init manager
            print("je suis la")
            print(octi_url)
            octi_manager = OpenCTIManagerAPI(
                url=octi_url,
                token=octi_token,
                ssl_verify=verify_ssl
            )
            result = octi_manager.search_indicator(entity_identifier)
            print("got result")
            print(result)
            if result:
               
                result_list.append(result)
                json_results[entity_identifier] = {result}
                # enrich data 
                # Set risk level
                # if indicator_data['general'][indicator_type].get('threatAssessRating', 0) > 1:
                #    entity.is_suspicious = True
                
                
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
                
                #json_results[get_entity_original_identifier(entity)].update(
                #  {"execution_status": "success"}
                #)
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
