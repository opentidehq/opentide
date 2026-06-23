import os
import sys
from dataclasses import dataclass

import git 
sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.tide import OpenTide, DebugHelpers

@dataclass
class DebugEnvironment:
    """
    This class encapsultes all relevant data, attributes and behaviours related to
    debugging to facilitate local development
    """
    ENABLED = False
    if DebugHelpers().is_debug():
        ENABLED = True
        os.environ["DEBUG_ENABLED"] = "True"
    MDR_DEPLOYMENT_TEST_UUIDS = list(OpenTide.Configurations.Deployment.debug["mdr_test_uuids"])
    PROXY_ENABLED = OpenTide.Configurations.Deployment.debug["proxy_enabled"]
    SSL_ENABLED = OpenTide.Configurations.Deployment.debug["ssl_enabled"]