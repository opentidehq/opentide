from cbc_sdk.enterprise_edr import Report, IOC_V2, Watchlist
from cbc_sdk.rest_api import CBCloudAPI
from opentide.generation.framework import techniques_resolver
from opentide.core.logging import log
from opentide.core.debug import DebugEnvironment
from opentide.core.registry import OpenTide
from opentide.platforms.plugins import RuleDeployer
from opentide.platforms.carbon_black.client import CarbonBlackCloudConnection
from opentide.deployment import check_status
from opentide.models.deployment_enums import DeploymentStrategy, StatusStrategy

class CarbonBlackCloudDeploy(CarbonBlackCloudConnection, RuleDeployer):

    def deploy_mdr(self, data):
        """
        Deployment routine, connecting to the platform and combining base and custom configurations
        """
        custom_orgs = data['configurations'][self.DEPLOYER_IDENTIFIER].get('organization')
        if custom_orgs:
            deploy_orgs = custom_orgs
        else:
            deploy_orgs = self.ORGANIZATIONS
        for org in deploy_orgs:
            log('ONGOING', f" Currently deploying MDR {data['name']} on organization", org)
            org = org.strip()
            if org in self.CBC_SECRETS:
                org_secrets = self.CBC_SECRETS[org]
                org_key = org_secrets.get('org_key')
                token = org_secrets.get('token')
            else:
                log('FATAL', 'Target organization is not present in Secrets configuration', org, 'Double check TOML config to ensure there is a org_key and token entry for this org')
                raise Exception
            if not org_key:
                log('FATAL', 'Could not fetch Organization Key for organization', org, 'Double check that there is a namespaced entry for this organization in the TOML config')
                raise Exception
            if not token:
                log('FATAL', 'Could not fetch Organization Token for organization', org, 'Double check that there is a namespaced entry for this organization in the TOML config')
                raise Exception
            try:
                service = CBCloudAPI(url=self.CBC_URL, token=token, org_key=org_key, ssl_verify=self.SSL_ENABLED)
                log('SUCCESS', 'Successfully connected to Carbon Black Cloud on tenant', org)
            except Exception:
                raise Exception(f' [FAILURE] Service could not be reached for organization {org}')
            config_data = data['configurations'][self.DEPLOYER_IDENTIFIER]
            uuid = data.get('uuid') or data['metadata']['uuid']
            name = data['name'].strip()
            description = data['description'].strip()
            status = config_data['status']
            query = config_data['query'].replace('\n', ' ')
            deployment = False
            removal = False
            if check_status(status) in (StatusStrategy.DISABLEMENT, StatusStrategy.DELETION):
                removal = True
            else:
                deployment = True
            tags = list()
            tags.append(config_data['status'])
            if 'detection_model' in data.keys():
                detection_model = data['detection_model']
                techniques = techniques_resolver(uuid)
                tags.append(detection_model)
                tags.extend(techniques)
            if 'tags' in config_data.keys():
                tags.extend(config_data['tags'])
            severity = self.SEVERITY_MAPPING[data['response']['alert_severity']]
            selected_watchlist = config_data.get('watchlist') or self.DEFAULT_WATCHLIST
            selected_report = config_data.get('report') or name
            watchlist_list = service.select(Watchlist)
            report = None
            watchlist = None
            if watchlist_list:
                for w in watchlist_list:
                    if w.name == selected_watchlist:
                        watchlist = w
                if watchlist:
                    for r in watchlist.reports:
                        if r.title == selected_report:
                            report = r
                else:
                    raise Exception(f' [FATAL] The CBC Deployer cannot create a detection in a nonexistent Watchlist : {selected_watchlist}. Make sure to createone on the console before retriggering the deployment')
            ioc = IOC_V2.create_query(service, uuid, query)
            if report:
                if selected_report == name:
                    if deployment:
                        report.remove_iocs_by_id(str(uuid))
                        report.append_iocs([ioc])
                        if severity != report.severity:
                            report.update(description=description, tags=tags, severity=severity)
                            log('INFO', 'Upgraded severity for this report to allign with MDR', str(severity))
                        else:
                            report.update(description=description, tags=tags)
                        log('SUCCESS', 'Rolled out IOC to report', selected_report)
                    elif removal:
                        report.delete()
                        log('WARNING', 'The report was deleted alongside the rule', selected_report)
                elif deployment:
                    report.remove_iocs_by_id(uuid)
                    report.append_iocs([ioc])
                    tags.extend((t for t in report.tags if t not in tags))
                    if severity > report.severity:
                        report.update(description=description, tags=tags, severity=severity)
                        log('INFO', 'Upgraded severity for this report to allign with MDR', str(severity))
                    else:
                        report.update(description=description, tags=tags)
                    log('SUCCESS', 'Deployed IOC to report', selected_report)
                elif removal:
                    if len(report.iocs_) > 1:
                        report.remove_iocs_by_id(uuid)
                        report.update()
                        log('SUCCESS', f'Deleted IOC from report', selected_report)
                    else:
                        report.delete()
                        log('WARNING', 'The specified report was automaticallydeleted as they were no other rule', selected_report)
            elif deployment:
                report_builder = Report.create(service, selected_report, description, severity)
                report_builder.add_ioc(ioc)
                for tag in tags:
                    report_builder.add_tag(tag.strip())
                report = report_builder.build()
                report.save_watchlist()
                watchlist.add_reports([report])
                log('SUCCESS', 'Created report and deployed IOC', selected_report)
            elif removal:
                log('SKIP', f'No report to delete, already removed from system', selected_report)
        return True

    def deploy(self, deployment: list[str], deployment_plan: DeploymentStrategy | None = None):
        if not deployment:
            raise Exception('DEPLOYMENT NOT FOUND')
        self.configure_proxy()
        for mdr in deployment:
            mdr_data = OpenTide.Models.rules[mdr]
            if self.DEPLOYER_IDENTIFIER in mdr_data['configurations'].keys():
                self.deploy_mdr(mdr_data)
            else:
                log('SKIP', f' Skipping as does not contain a CBC rule', mdr_data.get('name'))

def declare():
    return CarbonBlackCloudDeploy()
if __name__ == '__main__' and DebugEnvironment.ENABLED:
    CarbonBlackCloudDeploy().deploy(DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS)
