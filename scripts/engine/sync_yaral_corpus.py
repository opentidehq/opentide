#!/usr/bin/env python3
"""Vendor public YARA-L rules for the external corpus (yara-l-1.0).

Copies each listed community rule, unmodified, from a checkout of
chronicle/detection-rules (Apache-2.0) at ``COMMIT`` into
``testdata/conformance/external/yaral/``, and writes its ``.broken.`` twin:
the same file with one injected fault, chosen by the file's place in the
list:

0. an unknown UDM field (``metadata.`` becomes ``metadata.x_`` on the first
   predicate that reads it), which Google's compiler refuses ("field ... does
   not exist");
1. a dangling ``and`` at the end of ``condition``, a syntax error;
2. a misspelled section label (``condition:`` becomes ``conditon:``).

Google publishes no offline compiler (scripts/oracles/README.md), so the
twins are faults the language spec and Google's pages both name.
``crates/opentide-yaral/tests/external_corpus.rs`` holds the engine to the
files: every public file parses and has no error beyond its listed
exceptions; every twin gets an error.

Usage:
    python -I scripts/sync_yaral_corpus.py --rules ../detection-rules [--check]
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "testdata" / "conformance" / "external" / "yaral"
COMMIT = "a49c3752f3f013e9ead85c7430b8f39369efacbf"

# Every sixth community rule in path order, plus one rule for each feature the
# sample would miss (options, cidr lists, sliding windows, non-existence,
# window functions, entity graph, data tables, any, raw strings, nocase), and
# the two whose findings the spec and Google's repository disagree on.
RULES = [
    "authentication/geoip_user_login_from_multiple_states_or_countries.yaral",
    "aws/cloudtrail/aws_backup_plan_deleted.yaral",
    "aws/cloudtrail/aws_delete_vpc_flow_logs.yaral",
    "aws/cloudtrail/aws_excessive_successful_discovery_events.yaral",
    "aws/cloudtrail/aws_iam_access_denied_discovery_events.yaral",
    "aws/cloudtrail/aws_lambda_update_function_code.yaral",
    "aws/cloudtrail/aws_privilege_escalation_using_iam_login_profile.yaral",
    "aws/cloudtrail/aws_ses_service_modification.yaral",
    "aws/cloudtrail/aws_successful_api_from_tor_exit_node.yaral",
    "aws/guardduty/aws_guardduty_black_hole_traffic_detected.yaral",
    "aws/guardduty/aws_guardduty_malicious_or_suspicious_file_executed.yaral",
    "gcp/gcp_admin_privileged_roles_added_to_service_accounts.yaral",
    "gcp/gcp_cloud_audit_logging_removed_from_all_services.yaral",
    "gcp/gcp_exempt_principals_from_audit_log.yaral",
    "gcp/gcp_iam_organization_policy_updated_or_deleted.yaral",
    "gcp/gcp_kms_decryption_by_unexpected_service_account.yaral",
    "gcp/gcp_multiple_service_apis_disabled.yaral",
    "gcp/gcp_unauthorized_gke_pod_token_endpoint_usage.yaral",
    "github/github_enterprise_audit_log_stream_destroyed.yaral",
    "github/github_invitation_sent_to_non_company_email_domain.yaral",
    "github/github_personal_access_token_created_from_tor_ip_address.yaral",
    "github/github_secret_scanning_disabled_or_bypassed.yaral",
    "microsoft/adfs/adfs_dkm_key_access.yaral",
    "microsoft/entra_id/entra_id_application_hard_deletion.yaral",
    "microsoft/entra_id/entra_id_group_deletion_success.yaral",
    "microsoft/graph_activity/ms_graph_application_endpoint_requests.yaral",
    "microsoft/graph_activity/ms_graph_failed_file_downloads_uniq_docs.yaral",
    "microsoft/graph_activity/ms_graph_mail_api_requests_top_n_messages.yaral",
    "microsoft/o365/o365_ADPowerShell_app_login_subsequent_activity.yaral",
    "microsoft/o365/o365_entra_id_application_creation.yaral",
    "microsoft/o365/o365_group_modification_add_member_success.yaral",
    "microsoft/o365/o365_login_activity_to_uncommon_mscloud_apps.yaral",
    "microsoft/o365/o365_persistent_login_activity_to_azure_ADPowerShell_app.yaral",
    "microsoft/o365/o365_recently_created_entra_id_user_assigned_roles.yaral",
    "microsoft/sharepoint/ttp_windows_sharepoint_cve_2025_53770_webshell_succeeded.yaral",
    "microsoft/sharepoint/ttp_windows_suspicious_filewrites_to_sharepoint_layouts.yaral",
    "microsoft/windows/convertto_securestring_cmdlet_usage_via_commandline.yaral",
    "microsoft/windows/currentversion_autorun_keys_modification.yaral",
    "microsoft/windows/finger_exe_execution.yaral",
    "microsoft/windows/hacktool_purpleknight_execution.yaral",
    "microsoft/windows/lsass_memory_access_by_tool_dump_keyword_name.yaral",
    "microsoft/windows/mitre_attack_T1021_002_windows_admin_share_with_user_enrichment.yaral",
    "microsoft/windows/new_run_key_pointing_to_suspicious_folder.yaral",
    "microsoft/windows/potential_remote_powershell_session_initiated.yaral",
    "microsoft/windows/process_memory_dump_via_comsvcs_dll.yaral",
    "microsoft/windows/recon_environment_enumeration_active_directory_cisa_report.yaral",
    "microsoft/windows/renamed_createdump_utility_execution.yaral",
    "microsoft/windows/shimcache_flush.yaral",
    "microsoft/windows/suspicious_powershell_in_registry_run_keys.yaral",
    "microsoft/windows/win_repeatedAuthFailure_thenSuccess_T1110_001_user_asset_entity.yaral",
    "network/network_traffic_to_specific_country.yaral",
    "okta/okta_multiple_users_logins_with_invalid_credentials_from_the_same_ip.yaral",
    "okta/okta_threatinsight_suspected_brute_force_attack.yaral",
    "okta/okta_user_logins_from_multiple_cities.yaral",
    "onelogin/onelogin_multiple_users_login_failures_from_the_same_ip.yaral",
    "sap/sap_account_unlocked_then_used_from_same_ip.yaral",
    "sap/sap_audit_log_volume_monitor.yaral",
    "sap/sap_btp_identity_provider_trust_manipulation.yaral",
    "sap/sap_btp_tenant_audit_log_silent.yaral",
    "sap/sap_btp_workzone_site_creation.yaral",
    "sap/sap_bulk_download_following_restricted_object_access.yaral",
    "sap/sap_critical_authorization_value_changed.yaral",
    "sap/sap_dialog_logon_from_unlisted_network_range.yaral",
    "sap/sap_function_module_testing_detected.yaral",
    "sap/sap_kerberos_spnego_replay_attempt.yaral",
    "sap/sap_multi_terminal_logon.yaral",
    "sap/sap_privileged_account_logon_sweep_from_single_ip.yaral",
    "sap/sap_security_audit_log_user_created_deleted_or_unlocked.yaral",
    "sap/sap_shared_source_ip_across_multiple_users.yaral",
    "sap/sap_user_master_record_modified.yaral",
    "threat_intel/google_safebrowsing_file_contacts_tor_exit_node.yaral",
    "threat_intel/ioc_hash_prevalence.yaral",
    "threat_intel/network_connection_first_seen_in_past_day.yaral",
    "threat_intel/vt_relationships_file_contacts_tor_ip.yaral",
    "threat_intel/whois_expired_domain_executable_downloaded.yaral",
    "workspace/google_workspace_application_added.yaral",
    "workspace/google_workspace_marketplace_allowlist_configuration.yaral",
    "workspace/google_workspace_new_trusted_domain_added.yaral",
    "workspace/google_workspace_user_ou_changed.yaral",
]


def broken(text: str, index: int) -> str:
    """The rule with one injected fault, by its place in the list."""
    kind = index % 3
    if kind == 0:
        found = re.search(r"(\$\w+)\.metadata\.", text)
        if found:
            return text[: found.end()] + "x_" + text[found.end() :]
        kind = 1
    if kind == 1:
        found = re.search(r"condition:\s*\n((?:.|\n)*?)\n\s*(?:options:|export:|})", text)
        last = found.group(1).rsplit("\n", 1)[-1] if found else "//"
        # Not after a comment, where `and` would be comment text.
        if found and "//" not in last and "/*" not in last:
            end = found.end(1)
            return text[:end] + " and" + text[end:]
    return re.sub(r"\bcondition:", "conditon:", text, count=1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--rules", type=Path, required=True, help="a chronicle/detection-rules checkout")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    head = subprocess.run(
        ["git", "-C", str(args.rules), "rev-parse", "HEAD"], capture_output=True, text=True, check=False
    ).stdout.strip()
    if head and head != COMMIT:
        print(f"warning: {args.rules} is at {head}, the corpus at {COMMIT}", file=sys.stderr)
    expected: dict[Path, str] = {}
    for index, rel in enumerate(RULES):
        source = args.rules / "rules" / "community" / rel
        text = source.read_text(encoding="utf-8")
        name = Path(rel).name
        stem = name.removesuffix(".yaral")
        expected[OUT / name] = text
        twin = broken(text, index)
        if twin == text:
            sys.exit(f"{rel}: no fault could be injected")
        expected[OUT / f"{stem}.broken.yaral"] = twin
    if args.check:
        stale = [p for p, t in expected.items() if not p.exists() or p.read_text(encoding="utf-8") != t]
        extra = [p for p in OUT.glob("*.yaral") if p not in expected]
        for p in stale + extra:
            print(f"{p.relative_to(ROOT)} differs; run scripts/sync_yaral_corpus.py", file=sys.stderr)
        return 1 if stale or extra else 0
    OUT.mkdir(parents=True, exist_ok=True)
    for p in OUT.glob("*.yaral"):
        p.unlink()
    for path, text in expected.items():
        path.write_text(text, encoding="utf-8")
    print(f"wrote {len(expected)} files to {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
