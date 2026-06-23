import os
import sys
from mitrecve import crawler
from opentide.core.registry import OpenTide
from opentide.deployment import Proxy
import structlog
from opentide.core.logging.console import emit_section
logger = structlog.get_logger('opentide.validation.cve')
TVM_MODEL_FIELD = OpenTide.Configurations.Global.data_fields['tvm']

def run():
    if OpenTide.Configurations.Documentation.cve.get('proxy'):
        Proxy.set_proxy()
    else:
        Proxy.unset_proxy()
    emit_section('CVE Validation')
    logger.info('checks_whether_the_cve_in_tvm_cve_fields_exist_in_public_vulnera')
    error_list = []
    for tvm in (index := OpenTide.Models.tvm):
        tvm_data = index[tvm]
        tvm_name = tvm_data['name']
        tvm_id = tvm_data.get('metadata', {}).get('uuid')
        cve_list = tvm_data[TVM_MODEL_FIELD].get('cve')
        if cve_list:
            broken_cve = []
            logger.info('found_cve_in_tvm', detail=f'[{tvm_id}] {tvm_name}')
            for cve in cve_list:
                try:
                    details = crawler.get_main_page(cve)
                    details = crawler.get_cve_detail(details)[0]
                    logger.info('found_cve_in_nvd', arg0=cve)
                except Exception as error:
                    logger.error('the_cve_was_not_found_in_nvd', arg0=cve, advice='Double check online if it exists')
                    broken_cve.append(cve)
            if broken_cve:
                error_list.append([tvm, broken_cve])
    if error_list:
        for error in error_list:
            logger.error('operation_failed', detail=f'Found invalid CVEs in {error[0]}', context_1=''.join(error[1]), advice='Double check validity online')
        os.environ['VALIDATION_ERROR_RAISED'] = 'True'
    else:
        logger.info('no_invalid_cve_detected_in_tvms')
if __name__ == '__main__':
    run()
