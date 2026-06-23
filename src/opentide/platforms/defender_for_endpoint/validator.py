import os
import re
from typing import Sequence, Union
from opentide.core.logging import log
from opentide.core.debug import DebugEnvironment
from opentide.platforms.plugins import QueryValidator
from opentide.core.registry import OpenTide, DetectionPlatforms
from opentide.models.rule import DetectionRule
from opentide.models.deployment_enums import DeploymentStrategy
from opentide.deployment import TideDeployment
from opentide.platforms.defender_for_endpoint.client import DefenderForEndpointService
TIMESTAMP_COLUMNS = {'Timestamp', 'TimeGenerated'}
DEFENDER_XDR_TIMESTAMP_COLUMNS = {'Timestamp'}
REPORT_ID_COLUMNS = {'ReportId'}
DEVICE_ID_COLUMNS = {'DeviceId'}
OBSERVATION_ID_COLUMNS = {'ObservationId'}
IMPACTED_ASSET_IDENTIFIER_COLUMNS = {'DeviceId', 'DeviceName', 'RemoteDeviceName', 'RecipientEmailAddress', 'SenderFromAddress', 'SenderMailFromAddress', 'SenderObjectId', 'RecipientObjectId', 'AccountObjectId', 'AccountSid', 'AccountUpn', 'InitiatingProcessAccountSid', 'InitiatingProcessAccountUpn', 'InitiatingProcessAccountObjectId'}
DEFENDER_XDR_TABLES = {'DeviceEvents': 'endpoint', 'DeviceFileCertificateInfo': 'endpoint', 'DeviceFileEvents': 'endpoint', 'DeviceImageLoadEvents': 'endpoint', 'DeviceInfo': 'endpoint', 'DeviceLogonEvents': 'endpoint', 'DeviceNetworkEvents': 'endpoint', 'DeviceNetworkInfo': 'endpoint', 'DeviceProcessEvents': 'endpoint', 'DeviceRegistryEvents': 'endpoint', 'AlertEvidence': 'alert', 'AlertInfo': 'alert', 'CampaignInfo': 'xdr', 'EmailAttachmentInfo': 'xdr', 'EmailEvents': 'xdr', 'EmailPostDeliveryEvents': 'xdr', 'EmailUrlInfo': 'xdr', 'FileMaliciousContentInfo': 'xdr', 'MessageEvents': 'xdr', 'MessagePostDeliveryEvents': 'xdr', 'MessageUrlInfo': 'xdr', 'UrlClickEvents': 'xdr', 'AADSignInEventsBeta': 'xdr', 'AADSpnSignInEventsBeta': 'xdr', 'CloudAppEvents': 'xdr', 'EntraIdSignInEvents': 'xdr', 'EntraIdSpnSignInEvents': 'xdr', 'IdentityAccountInfo': 'xdr', 'IdentityDirectoryEvents': 'xdr', 'IdentityInfo': 'xdr', 'IdentityLogonEvents': 'xdr', 'IdentityQueryEvents': 'xdr', 'OAuthAppInfo': 'xdr'}

def strip_kql_literals_and_comments(query: str) -> str:
    """
    Removes KQL comments and string literals before scanning table names.
    This avoids matching table names mentioned in comments or text constants.
    """
    query = re.sub('/\\*.*?\\*/', ' ', query, flags=re.DOTALL)
    query = re.sub('//.*', ' ', query)
    query = re.sub("@?'(?:''|[^'])*'", ' ', query)
    query = re.sub('@?"(?:""|[^"])*"', ' ', query)
    return query

def defender_xdr_tables_in_query(query: str) -> set[str]:
    """
    Returns known Defender XDR advanced hunting tables referenced by a query.
    """
    query = strip_kql_literals_and_comments(query)
    tables = set()
    for table in DEFENDER_XDR_TABLES:
        if re.search(f'(?<![\\w.]){re.escape(table)}(?!\\w)', query):
            tables.add(table)
    tables.update((table for table in re.findall('(?<![\\w.])(Observation\\w+)(?!\\w)', query) if table != 'ObservationId'))
    return tables

def required_column_groups(query: str) -> list[set[str]]:
    """
    Builds accepted column groups for Defender XDR custom detection output.
    Each returned set is an OR group: at least one column in each group must be
    present in the returned schema.
    """
    tables = defender_xdr_tables_in_query(query)
    categories = {'observation' if table.startswith('Observation') else DEFENDER_XDR_TABLES[table] for table in tables}
    groups = [DEFENDER_XDR_TIMESTAMP_COLUMNS if categories else TIMESTAMP_COLUMNS]
    if 'endpoint' in categories:
        groups.extend([DEVICE_ID_COLUMNS, REPORT_ID_COLUMNS])
    if 'observation' in categories:
        groups.append(OBSERVATION_ID_COLUMNS)
    if 'xdr' in categories or not categories:
        if REPORT_ID_COLUMNS not in groups:
            groups.append(REPORT_ID_COLUMNS)
    if 'endpoint' not in categories:
        groups.append(IMPACTED_ASSET_IDENTIFIER_COLUMNS)
    return groups

def missing_required_column_groups(query: str, returned_columns: set[str]) -> list[str]:
    missing = []
    for group in required_column_groups(query):
        if returned_columns.isdisjoint(group):
            missing.append(' or '.join(sorted(group)))
    return missing

def returned_schema_columns(response: dict) -> set[str]:
    returned_columns = {col.get('name') or col.get('Name') for col in response.get('schema', response.get('Schema', []))}
    returned_columns.discard(None)
    return returned_columns

class DefenderForEndpointQueryValidator(QueryValidator):

    def check_query(self, mdr: DetectionRule, service: DefenderForEndpointService):
        config = mdr.configurations.defender_for_endpoint
        if not config:
            raise ValueError(f'Missing MDE configuration for {mdr.name}')
        query = config.query
        mdr_name = mdr.name
        mdr_uuid = mdr.metadata.uuid
        try:
            response = service.run_hunting_query(query)
        except Exception:
            os.environ['VALIDATION_ERROR_RAISED'] = 'True'
            return
        returned_columns = returned_schema_columns(response)
        missing = missing_required_column_groups(query, returned_columns)
        if missing:
            log('FATAL', f"Defender XDR custom detection query is missing required columns: {', '.join(missing)}", f'{mdr_name} ({mdr_uuid})', f"Detected Defender XDR tables: {', '.join(sorted(defender_xdr_tables_in_query(query))) or 'none'}", 'Per Microsoft documentation, Defender XDR custom detection queries must include Timestamp or TimeGenerated, event identity columns for the queried table family, and a supported impacted asset identifier in the output. See: https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules')
            os.environ['VALIDATION_ERROR_RAISED'] = 'True'

    def validate(self, mdr_deployment: Union[Sequence[DetectionRule], Sequence[str]], deployment_plan: DeploymentStrategy):
        if type(mdr_deployment[0]) is str:
            mdr_deployment = [OpenTide.Rules[uuid] for uuid in mdr_deployment]
        deployment = TideDeployment(deployment=mdr_deployment, system=DetectionPlatforms.DEFENDER_FOR_ENDPOINT, strategy=deployment_plan)
        for tenant_deployment in deployment.rule_deployment:
            service = DefenderForEndpointService(tenant_deployment.tenant)
            for mdr in tenant_deployment.rules:
                self.check_query(mdr=mdr, service=service)

def declare():
    return DefenderForEndpointQueryValidator()
if __name__ == '__main__' and DebugEnvironment.ENABLED:
    DefenderForEndpointQueryValidator().validate(DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS, DeploymentStrategy.DEBUG)
