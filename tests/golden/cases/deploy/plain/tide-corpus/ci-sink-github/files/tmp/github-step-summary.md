### ! opentide deploy --dry-run

Plan: 4 to create, 0 to update, 6 to create or update, 0 to disable, 0 to delete

Strategies: `PREVIEW`

| Platform | Tenant | Rules |
|---|---|---|
| `sentinel` | none | 2 |
| `defender_for_endpoint` | none | 1 |
| `splunk` | none | 1 |
| `sentinel_one` | none | 1 |
| `carbon_black_cloud` | none | 1 |
| `crowdstrike` | none | 1 |
| `harfanglab` | none | 1 |
| `elastic` | staging | 1 |
| `sysdig` | staging | 1 |

<details><summary>sentinel: 2 rules</summary>

- Sentinel KQL Rule (`00000000-0000-4000-8003-000000000001`)
- Staging Promote Rule (`00000000-0000-4000-8003-000000000008`)

</details>

<details><summary>defender_for_endpoint: 1 rule</summary>

- Defender KQL Rule (`00000000-0000-4000-8003-000000000002`)

</details>

<details><summary>splunk: 1 rule</summary>

- Splunk SPL Rule (`00000000-0000-4000-8003-000000000003`)

</details>

<details><summary>sentinel_one: 1 rule</summary>

- SentinelOne S1QL Rule (`00000000-0000-4000-8003-000000000004`)

</details>

<details><summary>carbon_black_cloud: 1 rule</summary>

- Carbon Black Lucene Rule (`00000000-0000-4000-8003-000000000005`)

</details>

<details><summary>crowdstrike: 1 rule</summary>

- CrowdStrike Deploy Rule (`00000000-0000-4000-8003-000000000006`)

</details>

<details><summary>harfanglab: 1 rule</summary>

- HarfangLab Deploy Rule (`00000000-0000-4000-8003-000000000007`)

</details>

<details><summary>elastic: 1 rule</summary>

- Elastic KQL Rule (`00000000-0000-4000-8003-000000000009`)

</details>

<details><summary>sysdig: 1 rule</summary>

- Sysdig Falco Rule (`00000000-0000-4000-8003-0000005d1a90`)

</details>

