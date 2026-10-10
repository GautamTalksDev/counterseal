import test from "node:test";
import assert from "node:assert";
import { makeAsk, readApproval, failureText } from "../mcp-ask.mjs";

const validApprovalFixture = (overrides = {}) => ({
    id: 'approval_434',
    hash: 'a'.repeat(64),
    status: 'pending',
    approve_url: 'https://counterseal.example/approve/approval_123',
    expires_at: 1_800_000_000,
  ...overrides,
}); 

test('readApproval validates the required fields and returns only safe approval data', async (t) => {
  await t.test('accepts a valid approval body', () => {
    assert.deepEqual(readApproval(validApprovalFixture()), {
      id: 'approval_123',
      hash: 'a'.repeat(64),
      status: 'pending',
      url: 'https://counterseal.example/approve/approval_123',
      expiresAt: 1_800_000_000,
    })
  })
});

  await t.test('rejects a bad id', () => {
    assert.equal(readApproval(validApprovalFixture({ id: 'bad/id' })), null);
  });


  await t.test('rejects a bad hash', () => {
    assert.equal(readApproval(validApprovalFixture({ hash: 'g'.repeat(64) })), null);
  });

  await t.test('does not accept a non-HTTP approve_url', () => {
    assert.deepEqual(
      readApproval(validApprovalFixture({ approve_url: 'javascript:alert(1)' })),
      {
        id: 'approval_123',
        hash: 'a'.repeat(64),
        status: 'pending',
        url: null,
        expiresAt: 1_800_000_000,
      },
    );
  });

  await t.test('returns null expiresAt when expires_at is missing', () => {
    const body = validApprovalFixture();
    delete body.expires_at;

    assert.equal(readApproval(body).expiresAt, null);
  });

test('failureText covers every status branch and sanitizes messages', async (t) => {
  await t.test('handles status 423', () => {
    assert.equal(
      failureText({ status: 423, body: {} }),
      'Counterseal is frozen: its owner stopped every agent and every approval. Do not retry until your human unfreezes it.',
    );
  });

  await t.test('handles status 401', () => {
    assert.equal(
      failureText({
        status: 401,
        body: { message: 'ignored message' },
      }),
      'The guard key was revoked or has ended. Your human can make a new one in the app (Account, Guard keys).',
    );
  });

  await t.test('handles status 429', () => {
    assert.equal(
      failureText({
        status: 429,
        body: { message: 'Review queue is full' },
      }),
      'Review queue is full',
    );
  });

  await t.test('uses the unreachable branch for status 0', () => {
    assert.equal(
      failureText({ status: 0, body: {}, error: 'TypeError' }),
      'Counterseal could not be reached (TypeError), so nothing can be approved right now.',
    );
  });

  await t.test('uses the unreachable branch for 5xx statuses', () => {
    assert.equal(
      failureText({ status: 503, body: {} }),
      'Counterseal could not be reached, so nothing can be approved right now.',
    );
  });

  await t.test('uses the default branch for other statuses', () => {
    assert.equal(
      failureText({
        status: 403,
        body: { message: 'Forbidden by guard' },
      }),
      'Forbidden by guard',
    );

    assert.equal(
      failureText({ status: 403, body: {} }),
      'Counterseal refused the request (403).',
    );
  });

  await t.test('replaces control characters in a message', () => {
    assert.equal(
      failureText({
        status: 429,
        body: { message: 'first\u0000second\u001fthird\u007fend' },
      }),
      'first second third end',
    );
  });

  await t.test('limits a long message to 300 characters', () => {
    const message = 'x'.repeat(350);
    const result = failureText({
      status: 429,
      body: { message },
    });

    assert.equal(result, 'x'.repeat(300));
    assert.equal(result.length, 300);
  });
});

test('makeAsk builds safe requests, clamps wait, URL-encodes ids, and handles fetch errors', async (t) => {
  await t.test('records requests with clamped wait values and URL-encoded ids', async () => {
    const calls = [];

    const fakeFetch = async (url, options) => {
      calls.push({ url, options });

      return {
        status: 200,
        json: async () => ({ ok: true }),
      };
    };

    const client = makeAsk({
      fetch: fakeFetch,
      server: 'https://counterseal.test',
      key: 'fake-counterseal-test-key',
      timeoutMs: 1_000,
      version: 'test',
    });

    const id = 'approval /? id';

    assert.deepEqual(await client.get(id, 99), {
      status: 200,
      body: { ok: true },
    });

    assert.deepEqual(await client.get(id, -1), {
      status: 200,
      body: { ok: true },
    });

    assert.equal(calls.length, 2);

    assert.equal(
      calls[0].url,
      'https://counterseal.test/v1/approvals/approval%20%2F%3F%20id?wait=20',
    );

    assert.equal(
      calls[1].url,
      'https://counterseal.test/v1/approvals/approval%20%2F%3F%20id?wait=0',
    );

    assert.equal(calls[0].options.method, 'GET');
    assert.equal(
      calls[0].options.headers.authorization,
      'Bearer fake-counterseal-test-key',
    );
    assert.equal(calls[0].options.headers.accept, 'application/json');
    assert.equal(
      calls[0].options.headers['user-agent'],
      'leash-mcp-wrap/test',
    );
    assert.equal(calls[0].options.redirect, 'error');
  });

  await t.test('returns status 0 when fetch throws', async () => {
    const client = makeAsk({
      fetch: async () => {
        throw new TypeError('fake network failure');
      },
      server: 'https://counterseal.test',
      key: 'another-fake-test-key',
    });

    assert.deepEqual(await client.get('approval_123'), {
      status: 0,
      body: {},
      error: 'TypeError',
    });
  });
});