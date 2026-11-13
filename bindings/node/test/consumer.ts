// A consumer of the generated declarations (index.d.ts): `npm test` type-checks
// it with `tsc --noEmit`, so a declaration that stops describing the API fails.
import { capabilities, Connection, main, platforms, runJson, TenantConfig, VERSION, Workspace } from '@opentide/opentide'
import type {
  Canceller,
  Capabilities,
  ConnectOptions,
  DeployOutcome,
  DeployPlanOptions,
  LintOptions,
  LiveCheck,
  QueryOptions,
  QueryResult,
  ValidateOptions,
} from '@opentide/opentide'

const options: ValidateOptions = { check: 'schema', files: ['objects/rules/a.yaml'], strict: true, queries: 'warn' }
const ws: Workspace = Workspace.open('.', { cwd: '.' })
const memory: Workspace = Workspace.fromFiles('/ws', { 'objects/rules/a.yaml': 'name: A\n' })
const root: string = ws.root

const validation = ws.validate(options)
const failed: boolean = validation.failed
const exitCode: number = validation.exitCode
const status: string = validation.checks['schema'].status

const lintOptions: LintOptions = { checks: ['metadata', 'filenames'], strict: false }
const lint = memory.lint(lintOptions)
const lintStatus: 'completed' | 'issues' | 'failed' = lint.status
const failure: string | null = lint.failureCode

const coverage = ws.coverage('T1059')
const covering: string[] = coverage.rules
const rules: any[] = ws.rules()
const families: number = ws.objectives().length + ws.threats().length

const planOptions: DeployPlanOptions = { strategies: ['PREVIEW'], platform: 'sentinel', keepDeprecated: false }
const plan = ws.deployPlan(planOptions)
const ok: boolean = plan.ok

const tree = runJson(['commands'])
const code: number = main(['--version'])
const version: string = VERSION

// The tenant operations: synchronous configuration, promises for the network.
const tenants: TenantConfig[] = ws.tenants('sentinel_one')
const inCode = new TenantConfig('sentinel_one', 'soc', { url: 'https://s1.example', api_token: '$S1_API_TOKEN' })
const keys: string[] = inCode.setupKeys
const connectOptions: ConnectOptions = { environment: { S1_API_TOKEN: 't' }, proxy: 'http://proxy:3128', timeout: 30 }
const connection: Connection = Connection.open(tenants[0] ?? inCode, connectOptions)
const can: Capabilities = connection.capabilities
const live: boolean = can.liveValidation
const known: string[] = platforms()
const sysdig: Capabilities | null = capabilities('sysdig')
const canceller: Canceller = connection.canceller()
const cancelled: boolean = canceller.isCancelled
const queryOptions: QueryOptions = { language: 's1ql', start: new Date(0).toISOString(), limit: 10, index: ['logs'], dataView: 'v', timeout: 60 }
const found: Promise<QueryResult> = connection.query('x', queryOptions)
const checked: Promise<LiveCheck> = connection.validateQuery('x')
const deployed: Promise<DeployOutcome> = connection.deploy('id', 'create', new Uint8Array())
async function read(): Promise<[string | null, string | null, string | null, Record<string, any>[]]> {
  const result = await found
  const check = await checked
  const outcome = await deployed
  return [result.columns[0]?.type ?? null, result.vendorQueryId, outcome.remoteId, check.result?.rows ?? []]
}

// @ts-expect-error: an operation deploy does not have
connection.deploy('id', 'upsert', '{}')
// @ts-expect-error: a check validate does not have
ws.validate({ check: 'everything' })
// @ts-expect-error: queries is error, warn or off
ws.validate({ queries: 'loud' })

export { cancelled, keys, known, live, read, sysdig }
export { covering, code, families, rules, exitCode, failed, failure, lintStatus, ok, root, status, tree, version }
