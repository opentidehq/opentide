correlate(
    // Search for whoami executions on Windows
    whoami: {
        #repo="base_sensor" #event_simpleName=ProcessRollup2 event_platform=Win FileName="whoami.exe"
    } include: [aid, ComputerName, FileName],
    // Search for net executions on Windows
    net: {
        #repo="base_sensor" #event_simpleName=ProcessRollup2 event_platform=Win FileName=/^net1?\.exe$/
          | aid <=> whoami.aid
          } include: [aid, ComputerName, FileName],
    // Search for systeminfo executions on Windows
    systeminfo: {
        #repo="base_sensor" #event_simpleName=ProcessRollup2 event_platform=Win FileName="systeminfo.exe"
          | aid <=> net.aid
          } include: [aid, ComputerName, FileName],
sequence=false, within=5m