import { fork, spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";
import zlib from "node:zlib";

export const STATE_MAGIC = Buffer.from("9RSTATE1", "ascii");
export const ALLOWED_STATE_FILES = ["db/data.sqlite", "machine-id", "jwt-secret", "auth/cli-secret"];

const DB_FILE = "db/data.sqlite";
const STATE_FILES = new Set(ALLOWED_STATE_FILES);
const STATE_LIMIT = 64 * 1024 * 1024;
const SCHEMA = {
  settings: ["id", "data"],
  apiKeys: ["id", "key", "name", "machineId", "isActive", "createdAt", "accessRestricted", "accessAllow"],
  combos: ["id", "name", "kind", "models", "createdAt", "updatedAt"],
};
const CHILD_ENV_ALLOWLIST = [
  "PATH",
  "SYSTEMROOT",
  "HOME",
  "USERPROFILE",
  "APPDATA",
  "LOCALAPPDATA",
  "TMPDIR",
  "TMP",
  "TEMP",
  "LANG",
  "LC_ALL",
  "TZ",
  "NODE_ENV",
  "NEXT_TELEMETRY_DISABLED",
  "AUTH_COOKIE_SECURE",
  "INITIAL_PASSWORD",
  "JWT_SECRET",
  "API_KEY_SECRET",
  "MACHINE_ID_SALT",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "ALL_PROXY",
  "NO_PROXY",
  "http_proxy",
  "https_proxy",
  "all_proxy",
  "no_proxy",
];
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const hash = (value) => crypto.createHash("sha256").update(value).digest();
const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

export function deriveEncryptionKey(secret) {
  return Buffer.from(
    crypto.hkdfSync("sha256", Buffer.from(String(secret), "utf8"), "malpdf-9router-salt", "9router-state-v1", 32),
  );
}

export function encryptStateBundle(filesMap, secret) {
  const json = Buffer.from(JSON.stringify({ version: 1, createdAt: new Date().toISOString(), files: filesMap }));
  if (json.length > STATE_LIMIT) throw new Error("State bundle exceeds the restore limit");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", deriveEncryptionKey(secret), iv);
  const ciphertext = Buffer.concat([cipher.update(zlib.gzipSync(json)), cipher.final()]);
  return Buffer.concat([STATE_MAGIC, iv, cipher.getAuthTag(), ciphertext]);
}

export function decryptStateBundle(rawBuffer, secret) {
  if (rawBuffer.length < 36 || !rawBuffer.subarray(0, 8).equals(STATE_MAGIC)) {
    throw new Error("Invalid state bundle header");
  }
  const decipher = crypto.createDecipheriv("aes-256-gcm", deriveEncryptionKey(secret), rawBuffer.subarray(8, 20));
  decipher.setAuthTag(rawBuffer.subarray(20, 36));
  const compressed = Buffer.concat([decipher.update(rawBuffer.subarray(36)), decipher.final()]);
  const bundle = JSON.parse(zlib.gunzipSync(compressed, { maxOutputLength: STATE_LIMIT }).toString("utf8"));
  if (
    !isObject(bundle) ||
    bundle.version !== 1 ||
    typeof bundle.createdAt !== "string" ||
    !Number.isFinite(Date.parse(bundle.createdAt)) ||
    !isObject(bundle.files)
  ) {
    throw new Error("Invalid state bundle structure");
  }
  for (const [name, content] of Object.entries(bundle.files)) {
    if (
      name.includes("..") ||
      name.startsWith("/") ||
      !STATE_FILES.has(name) ||
      typeof content !== "string" ||
      Buffer.from(content, "base64").toString("base64") !== content
    ) {
      throw new Error("Invalid state bundle file");
    }
  }
  return bundle;
}

function snapshotDigest(files) {
  const digest = crypto.createHash("sha256");
  for (const name of Object.keys(files).sort()) {
    const bytes = files[name];
    digest.update(`${name}\0${bytes.length}\0`).update(bytes);
  }
  return digest.digest("hex");
}

function statePath(dataDir, name) {
  let target = dataDir;
  for (const segment of ["", ...name.split("/")]) {
    target = path.join(target, segment);
    if (fs.lstatSync(target, { throwIfNoEntry: false })?.isSymbolicLink()) {
      throw new Error("Symlink in state path");
    }
  }
  return target;
}

function useDatabase(file, operation, readOnly = false) {
  const db = new DatabaseSync(file, { readOnly });
  try {
    db.exec("PRAGMA busy_timeout = 5000");
    return operation(db);
  } finally {
    db.close();
  }
}

function restoreFiles(dataDir, files) {
  const staging = statePath(dataDir, `.restore-staging-${process.pid}-${Date.now()}`);
  fs.mkdirSync(staging, { mode: 0o700 });
  try {
    const targets = Object.keys(files).map((name) => {
      const destination = statePath(dataDir, name);
      const existing = fs.lstatSync(destination, { throwIfNoEntry: false });
      if (existing && !existing.isFile()) throw new Error("Invalid restore target");
      const source = path.join(staging, name);
      fs.mkdirSync(path.dirname(source), { recursive: true, mode: 0o700 });
      fs.writeFileSync(source, files[name], { flag: "wx", mode: 0o600 });
      return { source, destination };
    });
    if (Object.hasOwn(files, DB_FILE)) {
      const validHeader = files[DB_FILE].subarray(0, 16).equals(Buffer.from("SQLite format 3\0"));
      const validDb =
        validHeader &&
        useDatabase(
          path.join(staging, DB_FILE),
          (db) => db.prepare("PRAGMA quick_check").get()?.quick_check === "ok",
          true,
        );
      if (!validDb) throw new Error("Invalid SQLite snapshot");
      const sidecars = ["-wal", "-shm"].map((suffix) => statePath(dataDir, DB_FILE + suffix));
      for (const sidecar of sidecars) fs.rmSync(sidecar, { force: true });
    }
    for (const { source, destination } of targets) fs.renameSync(source, destination);
  } finally {
    fs.rmSync(staging, { recursive: true, force: true });
  }
}

function bootstrap(dbPath, dataDir, machineIdSalt, apiKey, comboName, models) {
  const machineFile = statePath(dataDir, "machine-id");
  try {
    fs.writeFileSync(machineFile, crypto.randomUUID(), { flag: "wx", mode: 0o600 });
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
  }
  const machineId = hash(fs.readFileSync(machineFile, "utf8") + machineIdSalt)
    .toString("hex")
    .slice(0, 16);
  const now = new Date().toISOString();
  useDatabase(dbPath, (db) => {
    db.exec("BEGIN IMMEDIATE");
    const row = db.prepare("SELECT data FROM settings WHERE id = 1").get();
    const settings = JSON.parse(row?.data ?? "{}");
    if (!isObject(settings)) throw new Error("Invalid 9Router settings");
    settings.requireLogin = true;
    settings.requireApiKey = true;
    db.prepare("INSERT INTO settings(id, data) VALUES(1, ?) ON CONFLICT(id) DO UPDATE SET data = excluded.data").run(
      JSON.stringify(settings),
    );
    if (apiKey) {
      const existing = db
        .prepare("SELECT id FROM apiKeys WHERE name = 'malpdf-web' OR key = ? ORDER BY (key = ?) DESC, id LIMIT 1")
        .get(apiKey, apiKey);
      if (existing) {
        db.prepare(
          "UPDATE apiKeys SET key = ?, machineId = ?, isActive = 1, accessRestricted = 0, accessAllow = '[]' WHERE id = ?",
        ).run(apiKey, machineId, existing.id);
      } else {
        db.prepare(
          "INSERT INTO apiKeys(id, key, name, machineId, isActive, createdAt, accessRestricted, accessAllow) VALUES(?, ?, 'malpdf-web', ?, 1, ?, 0, '[]')",
        ).run(crypto.randomUUID(), apiKey, machineId, now);
      }
    }
    if (comboName && models.length && !db.prepare("SELECT id FROM combos WHERE name = ?").get(comboName)) {
      db.prepare("INSERT INTO combos(id, name, kind, models, createdAt, updatedAt) VALUES(?, ?, NULL, ?, ?, ?)").run(
        crypto.randomUUID(),
        comboName,
        JSON.stringify(models),
        now,
        now,
      );
    }
    db.exec("COMMIT");
  });
}

function jsonResponse(res, status, value) {
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  res.end(JSON.stringify(value));
}

function proxy(req, res, port) {
  const headers = { ...req.headers };
  // 9Router uses x-real-ip before x-forwarded-for when the peer is a loopback proxy.
  delete headers["x-real-ip"];
  headers["x-forwarded-for"] = req.socket.remoteAddress;
  res.socket?.setNoDelay(true);
  const upstream = http.request({ hostname: "127.0.0.1", port, method: req.method, path: req.url, headers });
  const fail = () => {
    if (res.destroyed) return;
    if (res.headersSent) res.destroy();
    else jsonResponse(res, 502, { error: "upstream_unavailable" });
  };
  upstream.once("error", fail);
  upstream.once("response", (response) => {
    response.once("error", fail);
    res.writeHead(response.statusCode, response.rawHeaders);
    res.flushHeaders();
    response.pipe(res);
  });
  req.once("error", () => upstream.destroy());
  res.once("close", () => upstream.destroy());
  req.pipe(upstream);
}

function makeSnapshot(dataDir, temp, previousDigest, secret) {
  for (const suffix of ["", "-wal", "-shm"]) statePath(dataDir, DB_FILE + suffix);
  useDatabase(path.join(dataDir, DB_FILE), (db) => db.prepare("VACUUM INTO ?").run(temp), true);
  const files = { [DB_FILE]: fs.readFileSync(temp) };
  for (const name of STATE_FILES) {
    if (name === DB_FILE) continue;
    try {
      files[name] = fs.readFileSync(statePath(dataDir, name));
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
  const digest = snapshotDigest(files);
  if (digest === previousDigest) return { digest };
  const encoded = Object.fromEntries(Object.entries(files).map(([name, bytes]) => [name, bytes.toString("base64")]));
  return { digest, content: encryptStateBundle(encoded, secret).toString("base64") };
}

async function snapshot(dataDir, previousDigest, secret, signal) {
  signal.throwIfAborted();
  const temp = statePath(dataDir, `.snap-${process.pid}-${Date.now()}.sqlite`);
  fs.writeFileSync(temp, "", { flag: "wx", mode: 0o600 });
  try {
    // SQLite and compression are synchronous, so isolate them from HTTP and shutdown deadlines.
    return await new Promise((resolve, reject) => {
      const worker = fork(fileURLToPath(import.meta.url), ["--snapshot"], {
        execArgv: [],
        stdio: ["ignore", "ignore", "ignore", "ipc"],
      });
      const abort = () => worker.kill("SIGKILL");
      signal.addEventListener("abort", abort, { once: true });
      let result;
      worker.once("message", (message) => {
        result = message;
      });
      worker.once("error", reject);
      worker.once("close", (code) => {
        signal.removeEventListener("abort", abort);
        if (signal.aborted) reject(signal.reason);
        else if (code === 0 && result) resolve(result);
        else reject(new Error("State snapshot failed"));
      });
      worker.send({ dataDir, temp, previousDigest, secret }, (error) => {
        if (error) abort();
      });
    });
  } finally {
    fs.rmSync(temp, { force: true });
  }
}

function settlesWithin(promise, ms) {
  if (ms <= 0) return Promise.resolve(false);
  let timer;
  const timeout = new Promise((resolve) => {
    timer = setTimeout(resolve, ms, false);
  });
  return Promise.race([promise.then(() => true), timeout]).finally(() => clearTimeout(timer));
}

export function createSupervisor(options = {}) {
  const env = process.env;
  const {
    dataDir = env.DATA_DIR || "/app/data",
    publicPort = Number(env.PORT || 7860),
    publicHost = env.HOSTNAME || "0.0.0.0",
    internalPort = Number(env.INTERNAL_PORT || 20129),
    serverCommand = process.execPath,
    serverArgs = [env.SERVER_SCRIPT || "/app/custom-server.js"],
    serverCwd = env.SERVER_CWD || "/app",
    serverEnv = {},
    hfStateRepo = env.HF_STATE_REPO || "",
    hfSyncToken = env.HF_SYNC_TOKEN || "",
    stateEncryptionKey = env.STATE_ENCRYPTION_KEY || "",
    hfHubBaseUrl = env.HF_HUB_BASE_URL || "https://huggingface.co",
    bootstrapApiKey = env.BOOTSTRAP_API_KEY || "",
    machineIdSalt = env.MACHINE_ID_SALT || "endpoint-proxy-salt",
    bootstrapComboName = env.BOOTSTRAP_COMBO_NAME || "malpdf-default",
    bootstrapComboModels = env.BOOTSTRAP_COMBO_MODELS || "cx/gpt-6.2-sol,cx/gpt-6-sol,qd/auto",
    syncIntervalMs = Number(env.SYNC_INTERVAL_SEC || 180) * 1000,
    startupTimeoutMs = 45000,
    shutdownBudgetMs = 8500,
    fetchTimeoutMs = 15000,
  } = options;
  const root = path.resolve(dataDir);
  const dbPath = path.join(root, DB_FILE);
  const hubUrl = hfHubBaseUrl.replace(/\/+$/, "");
  const repoUrl = `${hubUrl}/api/datasets/${hfStateRepo}`;
  const hubHeaders = { Authorization: `Bearer ${hfSyncToken}` };
  const apiKey = bootstrapApiKey.trim();
  const controlDigest = hash(`Bearer ${apiKey}`);
  const models = (Array.isArray(bootstrapComboModels) ? bootstrapComboModels : bootstrapComboModels.split(","))
    .map((model) => model.trim())
    .filter(Boolean);
  const startup = new AbortController();
  let restoreState = "disabled";
  let canSyncRemote = false;
  let inSync = false;
  let parentCommit = null;
  let lastSyncedDigest = null;
  let lastSyncedAt = null;
  let child;
  let childExit;
  let childExited = false;
  let server;
  let timer;
  let ready = false;
  let startPromise;
  let stopPromise;
  let activeSyncController;
  let syncPromise;

  function getStatus() {
    return { restoreState, canSyncRemote, inSync, parentCommit, lastSyncedDigest, lastSyncedAt };
  }

  async function fetchRestore(url, read) {
    for (let attempt = 0; attempt < 3; attempt++) {
      startup.signal.throwIfAborted();
      let response;
      try {
        response = await fetch(url, {
          headers: hubHeaders,
          signal: AbortSignal.any([startup.signal, AbortSignal.timeout(fetchTimeoutMs)]),
        });
        if (response.status === 200) return await read(response);
      } catch (error) {
        if (startup.signal.aborted || attempt === 2) throw error;
      }
      if (response && response.status !== 200) {
        await response.body?.cancel();
        if (attempt === 2 || ![502, 503, 504].includes(response.status)) throw new Error("Hub restore request failed");
      }
      await delay(400);
    }
  }

  async function restore() {
    if (!hfStateRepo || !hfSyncToken || !stateEncryptionKey) return;
    try {
      const meta = JSON.parse(await fetchRestore(repoUrl, (response) => response.text()));
      if (!/^[0-9a-f]{40}$/i.test(typeof meta?.sha === "string" ? meta.sha : "") || !Array.isArray(meta.siblings)) {
        throw new Error("Invalid dataset metadata");
      }
      if (meta.siblings.some((entry) => entry?.rfilename === "state.enc")) {
        const url = `${hubUrl}/datasets/${hfStateRepo}/resolve/${meta.sha}/state.enc`;
        const bytes = await fetchRestore(url, (response) => response.arrayBuffer());
        const bundle = decryptStateBundle(Buffer.from(bytes), stateEncryptionKey);
        const files = Object.fromEntries(
          Object.entries(bundle.files).map(([name, value]) => [name, Buffer.from(value, "base64")]),
        );
        startup.signal.throwIfAborted();
        restoreFiles(root, files);
        lastSyncedDigest = snapshotDigest(files);
        restoreState = "restored";
        inSync = true;
      } else {
        restoreState = "first_boot";
        inSync = false;
      }
      parentCommit = meta.sha;
      canSyncRemote = true;
    } catch {
      canSyncRemote = false;
      inSync = false;
      restoreState = "degraded";
      console.warn("9Router state restore could not be confirmed. Remote sync is disabled.");
    }
  }

  async function upload(signal) {
    inSync = false;
    const { digest, content } = await snapshot(root, lastSyncedDigest, stateEncryptionKey, signal);
    if (!content) {
      inSync = Boolean(parentCommit && lastSyncedDigest);
      return inSync;
    }
    const body = [
      { key: "header", value: { summary: "sync 9router state", ...(parentCommit ? { parentCommit } : {}) } },
      { key: "file", value: { content, path: "state.enc", encoding: "base64" } },
    ]
      .map((line) => JSON.stringify(line))
      .join("\n");
    const requestSignal = AbortSignal.any([signal, AbortSignal.timeout(fetchTimeoutMs)]);
    const response = await fetch(`${repoUrl}/commit/main`, {
      method: "POST",
      headers: { ...hubHeaders, "Content-Type": "application/x-ndjson" },
      body,
      redirect: "error",
      signal: requestSignal,
    });
    if (response.status !== 200) {
      const conflict = [409, 412].includes(response.status);
      if (conflict) void response.body?.cancel().catch(() => {});
      const message = conflict ? "" : await response.text();
      if (conflict || /parent\s*commit|commit conflict|a commit has happened since/i.test(message)) {
        canSyncRemote = false;
        inSync = false;
        console.warn("9Router state sync stopped after a Hub parent commit conflict.");
        return false;
      }
      throw new Error("Hub state commit failed");
    }
    const result = await response.json();
    signal.throwIfAborted();
    if (typeof result?.commitOid !== "string" || result.commitOid.length < 7)
      throw new Error("Invalid state commit ID");
    parentCommit = result.commitOid;
    lastSyncedDigest = digest;
    lastSyncedAt = new Date().toISOString();
    inSync = true;
    return true;
  }

  function beginSync(callerSignal) {
    if (!ready || !canSyncRemote) return Promise.resolve(false);
    if (syncPromise) return syncPromise;
    activeSyncController = new AbortController();
    const signal = callerSignal
      ? AbortSignal.any([activeSyncController.signal, callerSignal])
      : activeSyncController.signal;
    syncPromise = upload(signal)
      .catch(() => {
        inSync = false;
        if (!signal.aborted) console.warn("9Router state sync failed. The last confirmed snapshot is unchanged.");
        return false;
      })
      .finally(() => {
        activeSyncController = undefined;
        syncPromise = undefined;
      });
    return syncPromise;
  }

  function syncNow() {
    return stopPromise ? Promise.resolve(false) : beginSync();
  }

  function isAuthorizedControl(req) {
    return Boolean(apiKey) && crypto.timingSafeEqual(hash(req.headers.authorization ?? ""), controlDigest);
  }

  function handleRequest(req, res) {
    const url = req.url.split("?", 1)[0];
    const isStatus = req.method === "GET" && url === "/_supervisor/status";
    const isSync = req.method === "POST" && url === "/_supervisor/sync";
    const isStop = req.method === "POST" && url === "/_supervisor/stop";
    if (!isStatus && !isSync && !isStop) return proxy(req, res, internalPort);
    req.resume();
    if (!isAuthorizedControl(req)) return jsonResponse(res, 401, { error: "unauthorized" });
    if (isStatus) return jsonResponse(res, 200, { ok: true, ...getStatus() });
    if (isStop) {
      jsonResponse(res, 200, { ok: true, stopping: true });
      void stop("SIGTERM").then((code) => {
        if (isMain) process.exit(code);
      });
      return;
    }
    void syncNow().then((synced) => {
      if (!res.destroyed) jsonResponse(res, 200, { ok: Boolean(synced && canSyncRemote && inSync), ...getStatus() });
    });
  }

  async function waitForSchema() {
    const timeout = AbortSignal.timeout(startupTimeoutMs);
    const deadline = Date.now() + startupTimeoutMs;
    while (Date.now() < deadline) {
      startup.signal.throwIfAborted();
      const nextPoll = Date.now() + 250;
      let response;
      try {
        response = await fetch(`http://127.0.0.1:${internalPort}/api/settings/require-login`, {
          signal: AbortSignal.any([startup.signal, timeout, AbortSignal.timeout(250)]),
        });
        await response.body?.cancel();
      } catch {
        startup.signal.throwIfAborted();
      }
      const remaining = deadline - Date.now();
      if (response && remaining > 0 && fs.existsSync(dbPath)) {
        try {
          const hasSchema = useDatabase(
            dbPath,
            (db) => {
              db.exec(`PRAGMA busy_timeout = ${Math.min(5000, remaining)}`);
              return Object.entries(SCHEMA).every(([table, columns]) => {
                const actual = new Set(
                  db
                    .prepare(`PRAGMA table_info(${table})`)
                    .all()
                    .map((column) => column.name),
                );
                return columns.every((column) => actual.has(column));
              });
            },
            true,
          );
          if (Date.now() < deadline && hasSchema) return;
        } catch (error) {
          if (![5, 6].includes(error.errcode & 0xff)) throw error;
        }
      }
      await delay(Math.max(0, Math.min(nextPoll, deadline) - Date.now()));
    }
    throw new Error("9Router startup timed out waiting for the required SQLite schema");
  }

  async function run() {
    startup.signal.throwIfAborted();
    for (const directory of ["", "db", "auth"]) {
      fs.mkdirSync(statePath(root, directory), { recursive: true, mode: 0o700 });
    }
    await restore();
    startup.signal.throwIfAborted();
    for (const suffix of ["", "-wal", "-shm"]) statePath(root, DB_FILE + suffix);
    const mergedEnvSource = { ...env, ...serverEnv };
    const filteredChildEnv = {};
    for (const key of CHILD_ENV_ALLOWLIST) {
      if (mergedEnvSource[key] !== undefined) filteredChildEnv[key] = mergedEnvSource[key];
    }
    child = spawn(serverCommand, serverArgs, {
      cwd: serverCwd,
      env: { ...filteredChildEnv, PORT: String(internalPort), HOSTNAME: "127.0.0.1", DATA_DIR: root },
      stdio: "inherit",
    });
    childExit = new Promise((resolve) => {
      const exited = () => {
        childExited = true;
        resolve();
        if (startup.signal.aborted) return;
        startup.abort(new Error("9Router child exited unexpectedly"));
        if (ready) {
          console.error("9Router child exited unexpectedly.");
          if (isMain) process.exitCode = 1;
          void stop();
        }
      };
      child.once("error", exited);
      child.once("exit", exited);
    });
    await waitForSchema();
    startup.signal.throwIfAborted();
    bootstrap(dbPath, root, machineIdSalt, apiKey, bootstrapComboName.trim(), models);
    server = http.createServer(handleRequest);
    await new Promise((resolve, reject) => {
      const signal = startup.signal;
      const abort = () => reject(signal.reason);
      signal.addEventListener("abort", abort, { once: true });
      server.once("error", reject);
      server.listen({ port: publicPort, host: publicHost, signal }, () => {
        signal.removeEventListener("abort", abort);
        resolve();
      });
    });
    startup.signal.throwIfAborted();
    ready = true;
    timer = setInterval(() => {
      void syncNow();
    }, syncIntervalMs).unref();
    await syncNow();
    startup.signal.throwIfAborted();
  }

  async function shutdown() {
    const deadline = Date.now() + shutdownBudgetMs;
    const wait = (pending, ms) => settlesWithin(pending, Math.min(ms, deadline - Date.now() - 25));
    clearInterval(timer);
    server?.close();
    startup.abort(new Error("9Router supervisor is stopping"));
    if (child && !childExited) {
      child.kill("SIGTERM");
      const grace = Math.min(3500, Math.max(200, deadline - Date.now() - 2500));
      if (!(await wait(childExit, grace))) {
        child.kill("SIGKILL");
        await wait(childExit, 500);
      }
    }
    server?.closeAllConnections();
    if (syncPromise) {
      const grace = Math.min(1500, Math.max(100, deadline - Date.now() - 2000));
      if (!(await wait(syncPromise, grace)) && syncPromise) {
        activeSyncController.abort();
        await wait(syncPromise, 300);
      }
    }
    const rem = deadline - Date.now() - 250;
    if (!syncPromise && canSyncRemote && ready && rem > 300) {
      if (!(await wait(beginSync(AbortSignal.timeout(rem)), rem)) && syncPromise) {
        activeSyncController.abort();
        await wait(syncPromise, 200);
      }
    }
    return 0;
  }

  function stop(_signal) {
    stopPromise ??= shutdown();
    return stopPromise;
  }

  function start() {
    startPromise ??= run().catch(async (error) => {
      await stop();
      throw error;
    });
    return startPromise;
  }

  return { start, stop, syncNow, getStatus };
}

const isMain = Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain && process.send && process.argv[2] === "--snapshot") {
  process.once("message", ({ dataDir, temp, previousDigest, secret }) => {
    try {
      process.send(makeSnapshot(dataDir, temp, previousDigest, secret), () => process.disconnect());
    } catch {
      process.exitCode = 1;
      process.disconnect();
    }
  });
} else if (isMain) {
  const supervisor = createSupervisor();
  let stopping = false;
  for (const signal of ["SIGTERM", "SIGINT"]) {
    process.on(signal, () => {
      stopping = true;
      void supervisor.stop(signal).then((code) => process.exit(code));
    });
  }
  supervisor.start().catch((error) => {
    if (stopping) return;
    console.error("9Router supervisor startup failed:", error.name === "Error" ? error.message : error.name);
    process.exitCode = 1;
  });
}
