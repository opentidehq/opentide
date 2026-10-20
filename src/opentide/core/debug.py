import os
from dataclasses import dataclass
from opentide.core import registry
from opentide.core.environment import DebugHelpers


class _DebugSetting:
    """Read a ``[debug]`` key of the deployment configuration on access (#539).

    A plain class attribute is evaluated when the module is imported. Every
    platform client, deployer and validator imports this module, so reading the
    configuration there built the registry index as a side effect of loading
    any engine, and bound whichever ``registry.Opentide`` was live at the time.
    """

    def __init__(self, key, convert=None):
        self._key = key
        self._convert = convert

    def __get__(self, obj, owner=None):
        value = registry.Opentide.Configurations.Deployment.debug[self._key]
        return self._convert(value) if self._convert else value


@dataclass
class DebugEnvironment:
    """
    This class encapsultes all relevant data, attributes and behaviours related to
    debugging to facilitate local development
    """
    ENABLED = False
    if DebugHelpers().is_debug():
        ENABLED = True
        os.environ['DEBUG_ENABLED'] = 'True'
    MDR_DEPLOYMENT_TEST_UUIDS = _DebugSetting('mdr_test_uuids', list)
    SSL_ENABLED = _DebugSetting('ssl_enabled')
