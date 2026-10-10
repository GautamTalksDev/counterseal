// Text the homepage demos show, copied from the product's own messages (the file each comes from is beside it).
// Placeholders in angle brackets in the originals are filled with demo values here.
const LINK = 'https://counterseal.gautamkhosla.com/app#hold=4f2a…';
const usd = (c) => '$' + (c / 100).toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
const G = 'Counterseal Deploy Gate: ';
export const STRINGS = {
  // cli/guard.mjs (what the agent reads when a command is held, and the waiting line on the terminal)
  guardHeld: `Counterseal held this command: <why> Ask your human to approve it at ${LINK}, then run exactly the same command again. Do not look for another way to do the same thing.`,
  guardWaiting: 'Counterseal: waiting for your passkey',
  // cli/mcp-wrap.mjs (the tool result the client gets for a held call)
  mcpHeld: `Held by Counterseal: <tool> needs approval (<why>). Ask your human to approve it at ${LINK}, then call the same tool with the same arguments again.`,
  // site/public/app/app.js (a hold that needs two seals)
  teamNeeds: 'Needs 2 seals from 2 different owners or approvers, each with their own passkey.',
  teamOneOfTwo: (name) => `1 of 2 seals: approved by ${name}. Waiting for a second approver.`,
  teamApproved: 'Approved. The agent can retry that exact request once.',
  // server/src/channels.js holdText
  channelMessage: `Counterseal: deploy-bot needs approval for gh.delete (0 of 2 seals so far). Approve with your passkey: ${LINK}`,
  // action/deploy-gate/index.mjs
  gateLogStart: [
    ['Run ./.github/actions/counterseal-gate', 'g'],
    [G + 'asking for approval of this job (gate gate_9f3c).', ''],
    [G + 'this job is paused until the gate\'s owner approves it.', 'w'],
    [G + `Approve or deny with a passkey at: ${LINK}`, 'a'],
    [G + 'Waiting up to 30 minutes. This step fails if the request is denied or expires.', ''],
  ],
  gateLogApproved: [
    [G + 'approved with a passkey. A token for the gate\'s key (valid 15 minutes) is in the token output.', 'ok'],
    ['Run ./deploy.sh  (with the 15 minute Counterseal token, not the real key)', 'g'],
  ],
  gateLogDenied: [
    ['Error: ' + 'Denied by the approver.', 'x'],
    ['Error: Process completed with exit code 1.', 'x'],
  ],
  // server/src/brakes.js
  frozen: 'This Counterseal account is frozen: every agent token and every coding-agent approval is stopped. Its owner can unfreeze it with a passkey in the app.',
  trippedWhy: 'This token sent the same request more times in 5 minutes than its limit allows, so its breaker tripped. Its writes wait until you reset it with your passkey; reads still pass.',
  brakeWhy: {
    'brake.money-per-call': (a) => `Refund of ${usd(a)} is over this token's cap of ${usd(5000)} a call.`,
    'brake.money-per-day': (a, so) => `Refund of ${usd(a)} would take today's total to ${usd(so + a)}, over this token's cap of ${usd(50000)} a day (UTC).`,
  },
};
