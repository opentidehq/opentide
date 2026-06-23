import os
import sys
from pathlib import Path
import json
from typing import Any, Dict, Literal, Mapping, Optional, Sequence, Tuple, Union, overload
from functools import cache
from abc import ABC
from importlib import import_module
from copy import deepcopy
from dataclasses import dataclass, asdict
from opentide.indexing.indexer import indexer
from opentide.models.legacy import DetectionPlatforms, TideModels, SharedModels, ConfigurationModels, SystemConfig
from opentide.loading.objects import Objects
from opentide.loading.configurations import Configurations
from opentide.core.root import get_repo_root
import structlog
logger = structlog.get_logger('opentide.loading.config_loader')
ROOT = get_repo_root()

class ConfigurationsLoader:

    @staticmethod
    def load_statuses(statuses_configuration: list[dict]) -> Sequence[ConfigurationModels.Deployment.Status]:
        """
        Converts a list of status configuration dictionaries into a sequence of ConfigurationModels.Deployment.Status objects.
        Args:
            statuses_configuration (list[dict]): A list of dictionaries where each dictionary contains the parameters 
                                                   to instantiate a ConfigurationModels.Deployment.Status object.
        Returns:
            Sequence[ConfigurationModels.Deployment.Status]: A sequence of ConfigurationModels.Deployment.Status instances created 
                                                       from the provided configuration dictionaries.
        """
        Status = ConfigurationModels.Deployment.Status
        parsed_configuration = list()
        for status_configuration in statuses_configuration:
            parsed_configuration.append(Status(**status_configuration))
        return parsed_configuration

    @staticmethod
    def load_visibility(config: dict) -> Optional[Configurations.Visibility]:
        """Load visibility configuration from a dictionary into a strongly-typed dataclass.
        
        This method processes the visibility configuration which consists of three main components:
        1. Assets - Business or technical assets that generate logs
        2. Log Sources - Specific sources that can be queried for detection purposes
        3. Detectors - External detection capabilities from third-party tools and platforms
        
        Args:
            config: Dictionary containing the visibility configuration with 'assets', 'logsources', and 'detectors' sections
            
        Returns:
            Configurations.Visibility: Populated dataclass if configuration exists
            None: If no visibility configuration is found
            
        Raises:
            ValueError: If the configuration is malformed, missing required fields,
                      or contains references to non-existent assets
        """
        if not config:
            return None
        try:
            assets = None
            asset_names = set()
            if (asset_configuration := config.get('assets')):
                assets = []
                for asset_config in asset_configuration:
                    asset = Configurations.Visibility.Asset(**asset_config)
                    assets.append(asset)
                    asset_names.add(asset.name)
            logsources = []
            for source_config in config.get('logsources', []):
                if (source_assets := source_config.get('assets')):
                    invalid_assets = [asset for asset in source_assets if asset not in asset_names]
                    if invalid_assets:
                        logger.error('operation_failed', detail=f"Log source '{source_config.get('name')}' references non-existent assets", context_1=f"Invalid assets: {', '.join(invalid_assets)}", advice='These assets must be defined in the assets section', arg2='Configuration will load but may be incomplete')
                logsources.append(Configurations.Visibility.LogSource(**source_config))
            detectors = []
            for detector_config in config.get('detectors', []):
                if (detector_assets := detector_config.get('assets')):
                    invalid_assets = [asset for asset in detector_assets if asset not in asset_names]
                    if invalid_assets:
                        logger.error('operation_failed', detail=f"Detector '{detector_config.get('name')}' references non-existent assets", context_1=f"Invalid assets: {', '.join(invalid_assets)}", advice='These assets must be defined in the assets section', arg2='Configuration will load but may be incomplete')
                detectors.append(Configurations.Visibility.Detector(**detector_config))
            return Configurations.Visibility(logsources=logsources if logsources else None, assets=assets if assets else None, detectors=detectors if detectors else None)
        except (KeyError, TypeError) as e:
            logger.critical('failed_to_load_visibility_configuration', detail=f'Error details: {str(e)}', advice='Ensure all required fields are present and properly formatted', arg2='Check the schema documentation for complete requirements')
            raise ValueError(f'Failed to load visibility configuration: {str(e)}')
