from __future__ import annotations

import json
from pathlib import Path
import subprocess

REPO_ROOT = Path(__file__).resolve().parents[1]
SUPERVISOR_MJS = REPO_ROOT / "production" / "9router_space" / "hf_supervisor.mjs"


def _run_node_harness(script: str, tmp_path: Path, timeout: float = 25.0) -> dict:
    result = subprocess.run(
        ["node", "--input-type=module", "-"],
        input=script,
        text=True,
        encoding="utf-8",
        capture_output=True,
        timeout=timeout,
        env={
            "PATH": subprocess.os.environ.get("PATH", ""),
            "SYSTEMROOT": subprocess.os.environ.get("SYSTEMROOT", ""),
            "TEST_ROOT": str(tmp_path),
            "SUPERVISOR_URI": SUPERVISOR_MJS.resolve().as_uri(),
        },
    )
    assert result.returncode == 0, f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    last_line = [ln for ln in result.stdout.splitlines() if ln.strip()][-1]
    return json.loads(last_line)


def test_supervisor_first_boot_pretraffic_gate_restore_and_conflict(tmp_path: Path) -> None:
    assert SUPERVISOR_MJS.is_file(), "Missing hf_supervisor.mjs"
    mock_child = tmp_path / "mock_9router.mjs"
    mock_child.write_text(
        """
import http from 'node:http';
import path from 'node:path';
import fs from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

const port = Number(process.env.PORT);
const host = process.env.HOSTNAME || '127.0.0.1';
const dataDir = process.env.DATA_DIR;
let db = null;

function ensureSchema() {
  if (db) return db;
  fs.mkdirSync(path.join(dataDir, 'db'), { recursive: true });
  db = new DatabaseSync(path.join(dataDir, 'db', 'data.sqlite'));
  db.exec('PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;');
  db.exec(`
    CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY, data TEXT);
    CREATE TABLE IF NOT EXISTS apiKeys (
      id TEXT PRIMARY KEY, key TEXT, name TEXT, machineId TEXT,
      isActive INTEGER, createdAt TEXT, accessRestricted INTEGER, accessAllow TEXT
    );
    CREATE TABLE IF NOT EXISTS combos (
      id TEXT PRIMARY KEY, name TEXT, kind TEXT, models TEXT, createdAt TEXT, updatedAt TEXT
    );
  `);
  return db;
}

const server = http.createServer((req, res) => {
  if (req.url === '/api/init' || req.url === '/api/health') {
    res.writeHead(200, {'Content-Type': 'application/json'});
    res.end(JSON.stringify({ok: true}));
    return;
  }
  if (req.url === '/api/settings/require-login') {
    const conn = ensureSchema();
    const row = conn.prepare('SELECT data FROM settings WHERE id = 1').get();
    const parsed = row ? JSON.parse(row.data) : {};
    res.writeHead(200, {'Content-Type': 'application/json'});
    res.end(JSON.stringify({requireLogin: parsed.requireLogin ?? true}));
    return;
  }
  if (req.url === '/v1/chat/completions') {
    const conn = ensureSchema();
    const sRow = conn.prepare('SELECT data FROM settings WHERE id = 1').get();
    const settings = sRow ? JSON.parse(sRow.data) : {};
    const auth = req.headers['authorization'] || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
    const keyRow = conn.prepare('SELECT isActive FROM apiKeys WHERE key = ?').get(token);
    if (settings.requireApiKey && (!keyRow || !keyRow.isActive)) {
      res.writeHead(401, {'Content-Type': 'application/json'});
      res.end(JSON.stringify({error: 'unauthorized'}));
      return;
    }
    const comboRow = conn.prepare('SELECT models FROM combos WHERE name = ?').get('malpdf-default');
    res.writeHead(200, {'Content-Type': 'application/json'});
    res.end(JSON.stringify({comboModels: comboRow ? JSON.parse(comboRow.models) : []}));
    return;
  }
  res.writeHead(404);
  res.end();
});

process.on('SIGTERM', () => { server.close(() => process.exit(0)); });
server.listen(port, host);
""",
        encoding="utf-8",
    )

    harness = r"""
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { DatabaseSync } from 'node:sqlite';

const mod = await import(process.env.SUPERVISOR_URI);
const root = process.env.TEST_ROOT;
const mockChild = path.join(root, 'mock_9router.mjs');

async function freePort() {
  return await new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const p = srv.address().port;
      srv.close((err) => err ? reject(err) : resolve(p));
    });
  });
}

let currentSha = '1'.repeat(40);
let storedStateBuf = null;
let commitCount = 0;
let stallUploads = false;
let forceDataset503 = false;

const hubServer = http.createServer((req, res) => {
  if (forceDataset503) {
    res.writeHead(503);
    res.end('hub unavailable');
    return;
  }
  if (req.method === 'GET' && req.url === '/api/datasets/DrStone113/malpdf-9router-state') {
    res.writeHead(200, {'Content-Type': 'application/json'});
    res.end(JSON.stringify({
      sha: currentSha,
      siblings: storedStateBuf ? [{rfilename: 'state.enc'}] : []
    }));
    return;
  }
  if (req.method === 'GET' && req.url.startsWith('/datasets/DrStone113/malpdf-9router-state/resolve/')) {
    const wantedSha = req.url.split('/resolve/')[1].split('/')[0];
    if (!storedStateBuf || wantedSha !== currentSha) {
      res.writeHead(404);
      res.end('missing');
      return;
    }
    res.writeHead(200, {'Content-Type': 'application/octet-stream'});
    res.end(storedStateBuf);
    return;
  }
  if (req.method === 'POST' && req.url === '/api/datasets/DrStone113/malpdf-9router-state/commit/main') {
    if (stallUploads) {
      return;
    }
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const lines = Buffer.concat(chunks).toString('utf8').trim().split(/\r?\n/).map((l) => JSON.parse(l));
      const parent = lines[0]?.value?.parentCommit;
      if (parent !== currentSha) {
        res.writeHead(412, {'Content-Type': 'application/json'});
        res.end(JSON.stringify({error: 'Precondition Failed: stale parentCommit'}));
        return;
      }
      const fileEntry = lines.find((x) => x.key === 'file');
      storedStateBuf = Buffer.from(fileEntry.value.content, 'base64');
      commitCount += 1;
      currentSha = String(commitCount + 1).padStart(40, '0');
      res.writeHead(200, {'Content-Type': 'application/json'});
      res.end(JSON.stringify({commitOid: currentSha}));
    });
    return;
  }
  res.writeHead(404);
  res.end();
});

await new Promise((r) => hubServer.listen(0, '127.0.0.1', r));
const hubUrl = `http://127.0.0.1:${hubServer.address().port}`;
const stateSecret = 'unit-test-encryption-secret-32bytes';
const bootstrapKey = '9r_unit_test_bootstrap_key_value';

try {
  const pub1 = await freePort();
  const int1 = await freePort();
  const dir1 = path.join(root, 'node1');
  const sup1 = mod.createSupervisor({
    dataDir: dir1,
    publicPort: pub1,
    publicHost: '127.0.0.1',
    internalPort: int1,
    serverCommand: process.execPath,
    serverArgs: [mockChild],
    serverCwd: root,
    hfStateRepo: 'DrStone113/malpdf-9router-state',
    hfSyncToken: 'hf_mock_token',
    stateEncryptionKey: stateSecret,
    hfHubBaseUrl: hubUrl,
    bootstrapApiKey: bootstrapKey,
    syncIntervalMs: 60000,
    shutdownBudgetMs: 3500,
  });
  await sup1.start();

  const unauth = await fetch(`http://127.0.0.1:${pub1}/v1/chat/completions`, { method: 'POST' });
  assert.equal(unauth.status, 401);

  const authed = await fetch(`http://127.0.0.1:${pub1}/v1/chat/completions`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${bootstrapKey}` },
  });
  assert.equal(authed.status, 200);
  const authedJson = await authed.json();
  assert.deepEqual(authedJson.comboModels, ['cx/gpt-6.2-sol', 'cx/gpt-6-sol', 'qd/auto']);

  {
    const db1 = new DatabaseSync(path.join(dir1, 'db', 'data.sqlite'));
    db1.prepare("INSERT INTO combos(id, name, kind, models, createdAt, updatedAt) VALUES('c2', 'persisted-combo', null, ?, 'now', 'now')").run(JSON.stringify(['qd/auto']));
    db1.close();
  }
  const syncResp = await fetch(`http://127.0.0.1:${pub1}/_supervisor/sync`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${bootstrapKey}` },
  });
  assert.equal(syncResp.status, 200);
  const syncMeta = await syncResp.json();
  assert.equal(syncMeta.canSyncRemote, true);
  assert.equal(syncMeta.parentCommit, currentSha);

  const pub2 = await freePort();
  const int2 = await freePort();
  const dir2 = path.join(root, 'node2');
  const sup2 = mod.createSupervisor({
    dataDir: dir2,
    publicPort: pub2,
    publicHost: '127.0.0.1',
    internalPort: int2,
    serverCommand: process.execPath,
    serverArgs: [mockChild],
    serverCwd: root,
    hfStateRepo: 'DrStone113/malpdf-9router-state',
    hfSyncToken: 'hf_mock_token',
    stateEncryptionKey: stateSecret,
    hfHubBaseUrl: hubUrl,
    bootstrapApiKey: bootstrapKey,
    syncIntervalMs: 60000,
    shutdownBudgetMs: 3500,
  });
  await sup2.start();
  assert.equal(sup2.getStatus().restoreState, 'restored');
  {
    const db2 = new DatabaseSync(path.join(dir2, 'db', 'data.sqlite'));
    const row = db2.prepare("SELECT name FROM combos WHERE id = 'c2'").get();
    assert.equal(row?.name, 'persisted-combo');
    db2.prepare("INSERT INTO combos(id, name, kind, models, createdAt, updatedAt) VALUES('c3', 'newer-combo', null, '[]', 'now', 'now')").run();
    db2.close();
  }
  await sup2.syncNow();
  const shaAfterNode2 = currentSha;

  {
    const db1 = new DatabaseSync(path.join(dir1, 'db', 'data.sqlite'));
    db1.prepare("INSERT INTO combos(id, name, kind, models, createdAt, updatedAt) VALUES('stale', 'stale-combo', null, '[]', 'now', 'now')").run();
    db1.close();
  }
  await sup1.syncNow();
  assert.equal(sup1.getStatus().canSyncRemote, false);
  assert.equal(currentSha, shaAfterNode2);
  await sup1.stop('SIGTERM');

  forceDataset503 = true;
  const pub3 = await freePort();
  const int3 = await freePort();
  const sup3 = mod.createSupervisor({
    dataDir: path.join(root, 'node3'),
    publicPort: pub3,
    publicHost: '127.0.0.1',
    internalPort: int3,
    serverCommand: process.execPath,
    serverArgs: [mockChild],
    serverCwd: root,
    hfStateRepo: 'DrStone113/malpdf-9router-state',
    hfSyncToken: 'hf_mock_token',
    stateEncryptionKey: stateSecret,
    hfHubBaseUrl: hubUrl,
    bootstrapApiKey: bootstrapKey,
    syncIntervalMs: 60000,
    shutdownBudgetMs: 2500,
    fetchTimeoutMs: 500,
  });
  await sup3.start();
  assert.equal(sup3.getStatus().canSyncRemote, false);
  assert.equal(sup3.getStatus().restoreState, 'degraded');
  forceDataset503 = false;
  await sup3.stop('SIGTERM');
  assert.equal(currentSha, shaAfterNode2);

  stallUploads = true;
  {
    const db2 = new DatabaseSync(path.join(dir2, 'db', 'data.sqlite'));
    db2.prepare("INSERT INTO combos(id, name, kind, models, createdAt, updatedAt) VALUES('c4', 'stall-test', null, '[]', 'now', 'now')").run();
    db2.close();
  }
  const hungSync = sup2.syncNow();
  await new Promise((r) => setTimeout(r, 150));
  const t0 = Date.now();
  await sup2.stop('SIGTERM');
  await hungSync.catch(() => {});
  const elapsedMs = Date.now() - t0;
  assert.ok(elapsedMs < 4200, `Shutdown exceeded budget: ${elapsedMs}ms`);

  console.log(JSON.stringify({ ok: true, commitCount, elapsedMs }));
} finally {
  hubServer.closeAllConnections?.();
  hubServer.close();
}
"""
    res = _run_node_harness(harness, tmp_path)
    assert res["ok"] is True
    assert res["commitCount"] >= 2
    assert res["elapsedMs"] < 4200
