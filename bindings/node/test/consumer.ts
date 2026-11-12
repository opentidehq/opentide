// A consumer of the generated declarations (index.d.ts): `npm test` type-checks
// it with `tsc --noEmit`, so a declaration that stops describing the API fails.
import { main, runJson, VERSION, Workspace } from '@opentide/opentide'
import type { DeployPlanOptions, LintOptions, ValidateOptions } from '@opentide/opentide'

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

const planOptions: DeployPlanOptions = { strategies: ['PREVIEW'], platform: 'sentinel', keepDeprecated: false }
const plan = ws.deployPlan(planOptions)
const ok: boolean = plan.ok

const tree = runJson(['commands'])
const code: number = main(['--version'])
const version: string = VERSION

// @ts-expect-error: a check validate does not have
ws.validate({ check: 'everything' })
// @ts-expect-error: queries is error, warn or off
ws.validate({ queries: 'loud' })

export { covering, code, exitCode, failed, failure, lintStatus, ok, root, status, tree, version }
