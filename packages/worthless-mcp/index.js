#!/usr/bin/env node
'use strict';

/**
 * worthless-mcp — thin Node.js wrapper around `uvx worthless[mcp] mcp`.
 *
 * Bootstraps uv on first run if it is not already installed, then execs the
 * MCP server over stdio.  Claude Code / Cursor / Windsurf pick this up via:
 *
 *   .mcp.json:
 *   { "mcpServers": { "worthless": { "command": "npx", "args": ["-y", "worthless-mcp"] } } }
 */

const { spawnSync, spawn, execFileSync } = require('child_process');
const { existsSync } = require('fs');
const path = require('path');
const os = require('os');

// Pin the Python package version to the same version as this npm package so
// the two halves always ship together.  uvx reuses a cached environment when
// the spec is identical, so subsequent launches are instant.
const { version: PKG_VERSION } = require('./package.json');
const PYTHON_SPEC = `worthless[mcp]==${PKG_VERSION}`;

const HOME_BIN = path.join(os.homedir(), '.local', 'bin');
const CARGO_BIN = path.join(os.homedir(), '.cargo', 'bin');

// ---------------------------------------------------------------------------
// Locate uvx
// ---------------------------------------------------------------------------

function findUvx() {
  // Fast-path: known install locations added by the uv installer.
  for (const dir of [HOME_BIN, CARGO_BIN]) {
    const bin = path.join(dir, process.platform === 'win32' ? 'uvx.exe' : 'uvx');
    if (existsSync(bin)) return bin;
  }

  // Fall back to PATH lookup.
  const which = process.platform === 'win32' ? 'where' : 'which';
  const r = spawnSync(which, ['uvx'], { encoding: 'utf8' });
  if (r.status === 0) {
    return r.stdout.trim().split('\n')[0].trim();
  }

  return null;
}

// ---------------------------------------------------------------------------
// Bootstrap uv (first-run only)
// ---------------------------------------------------------------------------

/**
 * Fetch a URL synchronously using a child Node process so we do not need
 * curl/wget at all.  Follows one level of redirects (astral.sh -> GitHub).
 */
function fetchSync(url) {
  const script = `
const https = require('https');
function get(u) {
  https.get(u, (r) => {
    if (r.statusCode >= 300 && r.statusCode < 400 && r.headers.location) {
      return get(r.headers.location);
    }
    let data = '';
    r.on('data', (c) => { data += c; });
    r.on('end', () => { process.stdout.write(data); });
  }).on('error', (e) => { process.stderr.write(e.message); process.exit(1); });
}
get(${JSON.stringify(url)});
`;
  return execFileSync(process.execPath, ['--eval', script], {
    encoding: 'utf8',
    timeout: 30_000,
  });
}

function bootstrapUv() {
  const platform = process.platform;
  log('uv not found — installing (one-time setup)...');

  if (platform === 'win32') {
    const r = spawnSync(
      'powershell',
      ['-NoProfile', '-Command', 'irm https://astral.sh/uv/install.ps1 | iex'],
      { stdio: ['ignore', 'ignore', 'inherit'] }
    );
    if (r.status !== 0) throw new Error('uv Windows install failed');
    return;
  }

  // macOS / Linux — prefer curl if available, otherwise use Node https.
  const hasCurl = spawnSync('curl', ['--version'], { encoding: 'utf8' }).status === 0;
  let installScript;
  if (hasCurl) {
    const r = spawnSync(
      'sh',
      ['-c', 'curl -LsSf https://astral.sh/uv/install.sh'],
      { encoding: 'utf8', timeout: 30_000 }
    );
    if (r.status !== 0) throw new Error('Failed to download uv installer');
    installScript = r.stdout;
  } else {
    installScript = fetchSync('https://astral.sh/uv/install.sh');
  }

  const r = spawnSync('sh', ['-s', '--', '--no-modify-path'], {
    input: installScript,
    stdio: ['pipe', 'ignore', 'inherit'],
  });
  if (r.status !== 0) throw new Error('uv installer exited with ' + r.status);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function log(msg) {
  process.stderr.write('[worthless-mcp] ' + msg + '\n');
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  const arg = process.argv[2];
  if (arg === '--version' || arg === '-v') {
    process.stdout.write(PKG_VERSION + '\n');
    process.exit(0);
  }
  if (arg === '--help' || arg === '-h') {
    process.stdout.write(
      'worthless-mcp ' + PKG_VERSION + '\n' +
      '\n' +
      'Thin npm wrapper that launches the Worthless MCP server.\n' +
      'Intended to be invoked by editors via .mcp.json:\n' +
      '\n' +
      '  { "command": "npx", "args": ["-y", "worthless-mcp"] }\n' +
      '\n' +
      'Flags:\n' +
      '  -v, --version   Print wrapper version (matches the pinned Python package)\n' +
      '  -h, --help      Show this message\n'
    );
    process.exit(0);
  }

  let uvx = findUvx();

  if (!uvx) {
    try {
      bootstrapUv();
    } catch (err) {
      log('Failed to install uv: ' + err.message);
      log('Install uv manually: https://docs.astral.sh/uv/getting-started/installation/');
      process.exit(1);
    }
    uvx = findUvx();
    if (!uvx) {
      log('uvx still not found after install — try opening a new terminal.');
      process.exit(1);
    }
    log('uv installed at ' + uvx);
  }

  // Pass stdio through — MCP protocol runs over stdin/stdout.
  const proc = spawn(uvx, [PYTHON_SPEC, 'mcp'], {
    stdio: 'inherit',
    shell: false,
  });

  proc.on('error', (err) => {
    log('spawn error: ' + err.message);
    process.exit(1);
  });

  proc.on('close', (code) => process.exit(code ?? 0));
}

main();
