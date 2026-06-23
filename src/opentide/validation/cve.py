import os
import sys

from mitrecve import crawler


from opentide.core.logging import log
from opentide.core.registry import OpenTide
from opentide.deployment import Proxy

TVM_MODEL_FIELD = OpenTide.Configurations.Global.data_fields["tvm"]


def run():
    if OpenTide.Configurations.Documentation.cve.get("proxy"):
        Proxy.set_proxy()
    else:
        Proxy.unset_proxy()

    log("TITLE", "CVE Validation")
    log(
        "INFO",
        "Checks whether the CVE in TVM cve fields exist in public vulnerability databases",
    )

    error_list = []
    for tvm in (index := OpenTide.Models.tvm):
        tvm_data = index[tvm]
        tvm_name = tvm_data["name"]
        tvm_id = tvm_data.get("metadata",{}).get("uuid")
        cve_list = tvm_data[TVM_MODEL_FIELD].get("cve")
        if cve_list:
            broken_cve = []
            log("INFO", "Found CVE in TVM", f"[{tvm_id}] {tvm_name}")
            for cve in cve_list:
                try:
                    details = crawler.get_main_page(cve)
                    details = crawler.get_cve_detail(details)[0]
                    log("SUCCESS", "Found CVE in NVD", cve)
                except Exception as error:
                    log(
                        "FAILURE",
                        "The CVE was not found in NVD",
                        cve,
                        "Double check online if it exists",
                    )
                    broken_cve.append(cve)

            if broken_cve:
                error_list.append([tvm, broken_cve])

    if error_list:
        for error in error_list:
            log(
                "FAILURE",
                f"Found invalid CVEs in {error[0]}",
                "".join((error[1])),
                "Double check validity online",
            )
        os.environ["VALIDATION_ERROR_RAISED"] = "True"

    else:
        log("SUCCESS", "No invalid CVE detected in TVMs")


if __name__ == "__main__":
    run()
