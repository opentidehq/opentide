"""Live query validation for Defender XDR: each rule's KQL, run for one row on its tenants.

On top of the hunting query's answer, the columns it returns must be the ones a
custom detection needs (:func:`missing_required_column_groups`).
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import ClassVar

from opentide.core.logging import get_logger
from opentide.models.rule import DetectionRule
from opentide.platforms.live_validation import LiveQueryValidator
from opentide.query.models import LiveCheck, QueryRequest

logger = get_logger(__name__)
TIMESTAMP_COLUMNS = {"Timestamp", "TimeGenerated"}
DEFENDER_XDR_TIMESTAMP_COLUMNS = {"Timestamp"}
REPORT_ID_COLUMNS = {"ReportId"}
DEVICE_ID_COLUMNS = {"DeviceId"}
OBSERVATION_ID_COLUMNS = {"ObservationId"}
IMPACTED_ASSET_IDENTIFIER_COLUMNS = {
    "DeviceId",
    "DeviceName",
    "RemoteDeviceName",
    "RecipientEmailAddress",
    "SenderFromAddress",
    "SenderMailFromAddress",
    "SenderObjectId",
    "RecipientObjectId",
    "AccountObjectId",
    "AccountSid",
    "AccountUpn",
    "InitiatingProcessAccountSid",
    "InitiatingProcessAccountUpn",
    "InitiatingProcessAccountObjectId",
}
DEFENDER_XDR_TABLES = {
    "DeviceEvents": "endpoint",
    "DeviceFileCertificateInfo": "endpoint",
    "DeviceFileEvents": "endpoint",
    "DeviceImageLoadEvents": "endpoint",
    "DeviceInfo": "endpoint",
    "DeviceLogonEvents": "endpoint",
    "DeviceNetworkEvents": "endpoint",
    "DeviceNetworkInfo": "endpoint",
    "DeviceProcessEvents": "endpoint",
    "DeviceRegistryEvents": "endpoint",
    "AlertEvidence": "alert",
    "AlertInfo": "alert",
    "CampaignInfo": "xdr",
    "EmailAttachmentInfo": "xdr",
    "EmailEvents": "xdr",
    "EmailPostDeliveryEvents": "xdr",
    "EmailUrlInfo": "xdr",
    "FileMaliciousContentInfo": "xdr",
    "MessageEvents": "xdr",
    "MessagePostDeliveryEvents": "xdr",
    "MessageUrlInfo": "xdr",
    "UrlClickEvents": "xdr",
    "AADSignInEventsBeta": "xdr",
    "AADSpnSignInEventsBeta": "xdr",
    "CloudAppEvents": "xdr",
    "EntraIdSignInEvents": "xdr",
    "EntraIdSpnSignInEvents": "xdr",
    "IdentityAccountInfo": "xdr",
    "IdentityDirectoryEvents": "xdr",
    "IdentityInfo": "xdr",
    "IdentityLogonEvents": "xdr",
    "IdentityQueryEvents": "xdr",
    "OAuthAppInfo": "xdr",
}


def strip_kql_literals_and_comments(query: str) -> str:
    """
    Removes KQL comments and string literals before scanning table names.
    This avoids matching table names mentioned in comments or text constants.
    """
    query = re.sub("/\\*.*?\\*/", " ", query, flags=re.DOTALL)
    query = re.sub("//.*", " ", query)
    query = re.sub("@?'(?:''|[^'])*'", " ", query)
    query = re.sub('@?"(?:""|[^"])*"', " ", query)
    return query


def defender_xdr_tables_in_query(query: str) -> set[str]:
    """
    Returns known Defender XDR advanced hunting tables referenced by a query.
    """
    query = strip_kql_literals_and_comments(query)
    tables = set()
    for table in DEFENDER_XDR_TABLES:
        if re.search(f"(?<![\\w.]){re.escape(table)}(?!\\w)", query):
            tables.add(table)
    tables.update(
        table
        for table in re.findall("(?<![\\w.])(Observation\\w+)(?!\\w)", query)
        if table != "ObservationId"
    )
    return tables


def required_column_groups(query: str) -> list[set[str]]:
    """
    Builds accepted column groups for Defender XDR custom detection output.
    Each returned set is an OR group: at least one column in each group must be
    present in the returned schema.
    """
    tables = defender_xdr_tables_in_query(query)
    categories = {
        "observation" if table.startswith("Observation") else DEFENDER_XDR_TABLES[table]
        for table in tables
    }
    groups = [DEFENDER_XDR_TIMESTAMP_COLUMNS if categories else TIMESTAMP_COLUMNS]
    if "endpoint" in categories:
        groups.extend([DEVICE_ID_COLUMNS, REPORT_ID_COLUMNS])
    if "observation" in categories:
        groups.append(OBSERVATION_ID_COLUMNS)
    if ("xdr" in categories or not categories) and REPORT_ID_COLUMNS not in groups:
        groups.append(REPORT_ID_COLUMNS)
    if "endpoint" not in categories:
        groups.append(IMPACTED_ASSET_IDENTIFIER_COLUMNS)
    return groups


def missing_required_column_groups(query: str, returned_columns: set[str]) -> list[str]:
    missing = []
    for group in required_column_groups(query):
        if returned_columns.isdisjoint(group):
            missing.append(" or ".join(sorted(group)))
    return missing


class DefenderForEndpointQueryValidator(LiveQueryValidator):
    platform: ClassVar[str] = "defender_for_endpoint"

    def inspect(
        self, rule: DetectionRule, request: QueryRequest, found: LiveCheck
    ) -> Sequence[str]:
        """The custom-detection columns the query's output lacks, as one error."""
        result = found.result
        returned = {column.name for column in result.columns} if result is not None else set()
        missing = missing_required_column_groups(request.text, returned)
        if not missing:
            return ()
        logger.critical(
            "defender_xdr_custom_detection_query_is_missing_required_columns",
            detail=f"{rule.name} ({rule.metadata.uuid})"
            " | "
            "Detected Defender XDR tables: "
            + (", ".join(sorted(defender_xdr_tables_in_query(request.text))) or "none")
            + " | "
            + (
                "Per Microsoft documentation, Defender XDR custom detection queries must "
                "include Timestamp or TimeGenerated, event identity columns for the queried "
                "table family, and a supported impacted asset identifier in the output. See: "
                "https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules"
            ),
        )
        return (f"the query's output lacks {'; '.join(missing)}",)


def declare() -> DefenderForEndpointQueryValidator:
    return DefenderForEndpointQueryValidator()
