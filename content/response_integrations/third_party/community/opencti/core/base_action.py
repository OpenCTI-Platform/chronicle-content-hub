from __future__ import annotations

from abc import ABC

from OpenCTIManager import OpenCTIManagerAPI
from TIPCommon.base.action import Action
from TIPCommon.extraction import extract_script_param, extract_configuration_param

from core.constants import INTEGRATION_NAME


class BaseAction(Action, ABC):
    """Base action class."""

    def _init_api_clients(self) -> OpenCTIManagerAPI:
        """Prepare API client"""
        # process integration param
        octi_url = extract_configuration_param(
            self.soar_action,
            provider_name=INTEGRATION_NAME,
            param_name="URL",
            print_value=True,
        )
        octi_token = extract_configuration_param(
            self.soar_action,
            provider_name=INTEGRATION_NAME,
            param_name="API Token",
            print_value=False,
        )
        verify_ssl = extract_configuration_param(
            self.soar_action,
            provider_name=INTEGRATION_NAME,
            param_name="Verify SSL",
            input_type=bool,
            print_value=True,
        )
        return OpenCTIManagerAPI(
            url=octi_url,
            token=octi_token,
            ssl_verify=verify_ssl
        )