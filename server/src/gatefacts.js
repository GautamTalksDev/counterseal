// What a deploy hold remembers about the GitHub Actions run it stands for, and the views of it: the hash the approval is
// bound to, the card the app shows, and the one optional public fact (the repository name, only if the owner opted in).
// Every value was checked to a strict shape from GitHub's signed token (oidc.js) before it was stored here; the one
// exception is `summary`, text the workflow itself sent, which is kept apart and labelled "not verified" wherever it is shown.
import { sha256hex } from './util.js';

export const GATE_AGENT = 'github-actions';
export const GATE_HOST = 'github.com';   // the host word of a deploy hold and its public receipt (fixed, never a repository)
export const GATE_METHOD = 'DEPLOY';     // the method word of a deploy hold and its public receipt
const REPO = /^[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}$/;
const DIGITS = /^[0-9]{1,20}$/;
const SHA = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;

/** the hash an approval of a deploy is bound to: the gate, the repository (GitHub's ids, not its name), the run and its
 *  attempt, the commit, the workflow (the file that runs and the job's own), the ref, the environment, the job */
export const gateHash = (f) => sha256hex(JSON.stringify(['v1', 'deploy', f.gate, f.repository_id, f.owner_id, f.run_id, f.run_attempt, f.sha, f.workflow_ref, f.job_workflow_ref, f.ref, f.environment || '', f.check_run_id || '']));

/** the facts stored in holds.context for a deploy hold: { gate: {...} } */
export function gateContext(g, c, { bind, publish, summary }) {
  return JSON.stringify({
    gate: {
      gate: g.id, repository: c.repository, repository_id: c.repository_id, owner_id: c.repository_owner_id,
      ref: c.ref, sha: c.sha, workflow_ref: c.workflow_ref, job_workflow_ref: c.job_workflow_ref, environment: c.environment,
      event: c.event_name, actor: c.actor, run_id: c.run_id, run_attempt: c.run_attempt, check_run_id: c.check_run_id,
      visibility: c.visibility, runner: c.runner, bind: bind ? 1 : 0, publish: publish ? 1 : 0, summary: summary || null,
    },
  });
}

/** the facts from a hold's context, or null if it is not a deploy hold's (or was dropped a day after the hold closed) */
export function factsOf(raw) {
  if (!raw) return null;
  let f;
  try { f = JSON.parse(raw).gate; } catch { return null; }
  if (!f || typeof f !== 'object') return null;
  const s = (v) => (typeof v === 'string' ? v : '');
  if (!REPO.test(s(f.repository)) || !DIGITS.test(s(f.repository_id)) || !DIGITS.test(s(f.owner_id)) || !SHA.test(s(f.sha)) || !DIGITS.test(s(f.run_id)) || !DIGITS.test(s(f.run_attempt))) return null;
  return {
    gate: s(f.gate), repository: f.repository, repository_id: f.repository_id, owner_id: f.owner_id, ref: s(f.ref), sha: f.sha,
    workflow_ref: s(f.workflow_ref), job_workflow_ref: s(f.job_workflow_ref), environment: s(f.environment), event: s(f.event), actor: s(f.actor),
    run_id: f.run_id, run_attempt: f.run_attempt, check_run_id: DIGITS.test(s(f.check_run_id)) ? f.check_run_id : '',
    visibility: s(f.visibility), runner: s(f.runner), bind: f.bind ? 1 : 0, publish: f.publish ? 1 : 0, summary: typeof f.summary === 'string' ? f.summary : null,
  };
}

/** the card the app shows. The links are built here from checked values, so the page never has to trust a URL. */
export function cardOf(raw) {
  const f = factsOf(raw);
  if (!f) return null;
  const { gate, owner_id, check_run_id, publish, ...rest } = f;
  return {
    ...rest,
    run_url: `https://github.com/${f.repository}/actions/runs/${f.run_id}/attempts/${f.run_attempt}`,
    commit_url: `https://github.com/${f.repository}/commit/${f.sha}`,
  };
}

/** the repository name for a public receipt: only when the owner opted in for this gate (default off), else nothing */
export const publicRepoOf = (raw) => { const f = factsOf(raw); return f && f.publish ? { public_repo: f.repository } : {}; };

/** the lines shown on a deploy hold (the preview): every line is from GitHub's signed token except the last, which is
 *  text the workflow sent and is labelled that way */
export function previewOf(f) {
  const lines = [];
  if (f.bind) lines.push(`First run of this gate: approving binds it to ${f.repository} (GitHub id ${f.repository_id}), so a renamed or re-created repository cannot use it.`, '');
  lines.push(
    `Repository: ${f.repository}${f.visibility ? ` (${f.visibility})` : ''}`,
    `Ref: ${f.ref}`,
    `Commit: ${f.sha}`,
    `Workflow: ${f.workflow_ref}`,
    ...(f.job_workflow_ref !== f.workflow_ref ? [`Job's workflow: ${f.job_workflow_ref}`] : []),
    `Environment: ${f.environment || '(none)'}`,
    `Started by: ${f.actor || '(unknown)'} (${f.event})`,
    `Run: https://github.com/${f.repository}/actions/runs/${f.run_id}/attempts/${f.run_attempt}`,
    ...(f.runner ? [`Runner: ${f.runner}`] : []),
    '', 'The lines above are from the token GitHub signed for this job.');
  if (f.summary) lines.push(`Text from the workflow (not verified): ${f.summary}`);
  return lines.join('\n');
}
