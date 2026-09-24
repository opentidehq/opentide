# External detection corpus

Full analytic rules are kept as authored. The v1 grammars accept a prefix of each rule (KQL `where` pipes before `summarize` assignments; SPL after a leading macro when the search is a field comparison). `external_corpus.rs` injects `frobnicate` or `notacommand` on that prefix and requires the unknown-operator or unknown-command diagnostic. The broken full file must also produce at least one diagnostic.

Queries are extracted from public detection content for conformance.
Each broken file is the same query with one injected fault.

## KQL — Azure/Azure-Sentinel (MIT)
- `ADFSDBNamedPipeConnection` from `Solutions` analytic rule `ADFSDBNamedPipeConnection.yaml`
- `ADFSDomainTrustMods` from `Solutions` analytic rule `ADFSDomainTrustMods.yaml`
- `ADFSRemoteAuthSyncConnection` from `Solutions` analytic rule `ADFSRemoteAuthSyncConnection.yaml`
- `ADFSRemoteHTTPNetworkConnection` from `Solutions` analytic rule `ADFSRemoteHTTPNetworkConnection.yaml`
- `ADFSSignInLogsPasswordSpray` from `Solutions` analytic rule `ADFSSignInLogsPasswordSpray.yaml`
- `AccountCreatedDeletedByNonApprovedUser` from `Solutions` analytic rule `AccountCreatedDeletedByNonApprovedUser.yaml`
- `AccountCreatedandDeletedinShortTimeframe` from `Solutions` analytic rule `AccountCreatedandDeletedinShortTimeframe.yaml`
- `AdminPromoAfterRoleMgmtAppPermissionGrant` from `Solutions` analytic rule `AdminPromoAfterRoleMgmtAppPermissionGrant.yaml`
- `AnomalousUserAppSigninLocationIncrease-detection` from `Solutions` analytic rule `AnomalousUserAppSigninLocationIncrease-detection.yaml`
- `ExcessiveLogonFailures` from `Solutions` analytic rule `ExcessiveLogonFailures.yaml`
- `ExchangeOABVirtualDirectoryAttributeContainingPotentialWebshell` from `Solutions` analytic rule `ExchangeOABVirtualDirectoryAttributeContainingPotentialWebshell.yaml`
- `GainCodeExecutionADFSViaSMB` from `Solutions` analytic rule `GainCodeExecutionADFSViaSMB.yaml`
- `LocalDeviceJoinInfoAndTransportKeyRegKeysAccess` from `Solutions` analytic rule `LocalDeviceJoinInfoAndTransportKeyRegKeysAccess.yaml`
- `MultipleFailedFollowedBySuccess` from `Solutions` analytic rule `MultipleFailedFollowedBySuccess.yaml`
- `SigninBruteForce` from `Solutions` analytic rule `SigninBruteForce.yaml`

## SPL — splunk/security_content (Apache-2.0)
- `7zip_commandline_to_smb_share_path` from `detections/endpoint/7zip_commandline_to_smb_share_path.yml`
- `access_lsass_memory_for_dump_creation` from `detections/endpoint/access_lsass_memory_for_dump_creation.yml`
- `active_directory_lateral_movement_identified` from `detections/endpoint/active_directory_lateral_movement_identified.yml`
- `active_directory_privilege_escalation_identified` from `detections/endpoint/active_directory_privilege_escalation_identified.yml`
- `active_setup_registry_autostart` from `detections/endpoint/active_setup_registry_autostart.yml`
- `add_defaultuser_and_password_in_registry` from `detections/endpoint/add_defaultuser_and_password_in_registry.yml`
- `add_or_set_windows_defender_exclusion` from `detections/endpoint/add_or_set_windows_defender_exclusion.yml`
- `adsisearcher_account_discovery` from `detections/endpoint/adsisearcher_account_discovery.yml`
- `advanced_ip_or_port_scanner_execution` from `detections/endpoint/advanced_ip_or_port_scanner_execution.yml`
- `allow_file_and_printing_sharing_in_firewall` from `detections/endpoint/allow_file_and_printing_sharing_in_firewall.yml`
- `allow_inbound_traffic_by_firewall_rule_registry` from `detections/endpoint/allow_inbound_traffic_by_firewall_rule_registry.yml`
- `allow_inbound_traffic_in_firewall_rule` from `detections/endpoint/allow_inbound_traffic_in_firewall_rule.yml`
- `allow_network_discovery_in_firewall` from `detections/endpoint/allow_network_discovery_in_firewall.yml`
- `allow_operation_with_consent_admin` from `detections/endpoint/allow_operation_with_consent_admin.yml`
