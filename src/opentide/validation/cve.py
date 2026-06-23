import os
from mitrecve import crawler
from opentide.core.logging import log
from opentide.core.registry import OpenTide
from opentide.deployment import Proxy
THREAT_MODEL_FIELD = 'threat'

def run():
    if OpenTide.Configurations.Documentation.cve.get('proxy'):
        Proxy.set_proxy()
    else:
        Proxy.unset_proxy()
    log('TITLE', 'CVE Validation')
    log('INFO', 'Checks whether the CVE in TVM cve fields exist in public vulnerability databases')
    error_list = []
    for threat_id in (index := OpenTide.Models.threats):
        threat_data = index[threat_id]
        threat_name = threat_data['name']
        threat_uuid = threat_data.get('metadata', {}).get('uuid')
        cve_list = threat_data[THREAT_MODEL_FIELD].get('cve')
        if cve_list:
            broken_cve = []
            log('INFO', 'Found CVE in threat vector', f'[{threat_uuid}] {threat_name}')
            for cve in cve_list:
                try:
                    crawler.get_cve_detail(crawler.get_main_page(cve))
                    log('SUCCESS', 'Found CVE in NVD', cve)
                except Exception as error:
                    log('FAILURE', 'The CVE was not found in NVD', cve, 'Double check online if it exists')
                    broken_cve.append(cve)
            if broken_cve:
                error_list.append([threat_id, broken_cve])
    if error_list:
        for error in error_list:
            log('FAILURE', f'Found invalid CVEs in {error[0]}', ''.join(error[1]), 'Double check validity online')
        os.environ['VALIDATION_ERROR_RAISED'] = 'True'
    else:
        log('SUCCESS', 'No invalid CVE detected in threat vectors')
if __name__ == '__main__':
    run()
