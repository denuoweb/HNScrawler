#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const {execFileSync} = require('child_process');
const {once} = require('events');

function usage() {
  return [
    'usage: hsd-nameonly-replay-jsonl.js --out <path> [options]',
    '',
    'Experimental name-only Handshake replay sidecar.',
    '',
    'Options:',
    '  --rpc-url <url>       HSD RPC URL. Default: HSD_RPC_URL or http://127.0.0.1:12037',
    '  --api-key <key>       HSD API key. Default: HSD_API_KEY',
    '  --out <path>          Output JSONL path.',
    '  --network <name>      HSD network name. Default: main',
    '  --from-height <n>     First block height to replay. Default: 0',
    '  --to-height <n>       Last block height to replay. Default: current HSD tip',
    '  --progress <n>        Emit progress every n blocks. Default: 1000',
    '  --reorg-window <n>    Emit block history for the last n replayed blocks. Default: 300',
    '  --limit-blocks <n>    Stop after n blocks for benchmarking.',
    '  --help                Show this help text.',
    '',
    'Environment:',
    '  HSD_MODULE_ROOT       Optional path to the installed hsd package root.',
    '  HSD_RPC_URL           Default RPC URL.',
    '  HSD_API_KEY           Default RPC API key.',
    '  HSD_NETWORK           Default network when --network is omitted.',
  ].join('\n');
}

function parseArgs(argv) {
  const args = {
    rpcUrl: process.env.HSD_RPC_URL || 'http://127.0.0.1:12037',
    apiKey: process.env.HSD_API_KEY || '',
    out: process.env.JSONL_PATH || '',
    network: process.env.HSD_NETWORK || 'main',
    fromHeight: 0,
    toHeight: null,
    progress: 1000,
    reorgWindow: 300,
    limitBlocks: null
  };

  for (let i = 0; i < argv.length; i++) {
    const item = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length)
        throw new Error(`${item} requires a value`);
      return argv[i];
    };

    switch (item) {
      case '--rpc-url':
        args.rpcUrl = next();
        break;
      case '--api-key':
        args.apiKey = next();
        break;
      case '--out':
        args.out = next();
        break;
      case '--network':
        args.network = next();
        break;
      case '--from-height':
        args.fromHeight = nonNegativeInt('--from-height', next());
        break;
      case '--to-height':
        args.toHeight = nonNegativeInt('--to-height', next());
        break;
      case '--progress':
        args.progress = nonNegativeInt('--progress', next());
        break;
      case '--reorg-window':
        args.reorgWindow = nonNegativeInt('--reorg-window', next());
        break;
      case '--limit-blocks':
        args.limitBlocks = positiveInt('--limit-blocks', next());
        break;
      case '--help':
      case '-h':
        console.log(usage());
        process.exit(0);
        break;
      default:
        throw new Error(`unknown argument: ${item}`);
    }
  }

  if (!args.out)
    throw new Error('--out is required');

  return args;
}

function nonNegativeInt(name, value) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isSafeInteger(parsed) || parsed < 0)
    throw new Error(`${name} must be a non-negative integer`);
  return parsed;
}

function positiveInt(name, value) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isSafeInteger(parsed) || parsed <= 0)
    throw new Error(`${name} must be a positive integer`);
  return parsed;
}

function discoverHsdRoot() {
  const candidates = [];

  if (process.env.HSD_MODULE_ROOT)
    candidates.push(process.env.HSD_MODULE_ROOT);

  candidates.push(path.join(process.cwd(), 'node_modules', 'hsd'));

  try {
    const npmRoot = execFileSync('npm', ['root', '-g'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore']
    }).trim();
    if (npmRoot)
      candidates.push(path.join(npmRoot, 'hsd'));
  } catch (e) {
    // npm is installed by the indexer setup script, but HSD_MODULE_ROOT is enough.
  }

  candidates.push('/usr/local/lib/node_modules/hsd');
  candidates.push('/usr/lib/node_modules/hsd');

  for (const candidate of candidates) {
    if (!candidate)
      continue;
    const root = path.resolve(candidate);
    if (fs.existsSync(path.join(root, 'package.json'))
        && fs.existsSync(path.join(root, 'lib', 'covenants', 'namestate.js'))) {
      return root;
    }
  }

  throw new Error(
    'could not locate installed hsd package; set HSD_MODULE_ROOT or run npm install -g hsd'
  );
}

function hsdRequire(hsdRoot, relativePath) {
  return require(path.join(hsdRoot, relativePath));
}

async function writeJsonLine(stream, value) {
  if (!stream.write(`${JSON.stringify(value)}\n`))
    await once(stream, 'drain');
}

async function closeStream(stream) {
  if (stream.closed || stream.destroyed)
    return;
  stream.end();
  await once(stream, 'finish');
}

function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function normalizeNS(ns) {
  return String(ns || '').trim().toLowerCase().replace(/\.+$/, '');
}

function normalizeAddress(address) {
  return String(address || '').trim();
}

function sorted(set) {
  return Array.from(set).sort();
}

function summarizeResourceData(data, Resource, hsTypesByVal) {
  const summary = {
    ns_names: [],
    glue4: [],
    glue6: [],
    synth4: [],
    synth6: [],
    ds_records: [],
    has_ds: false,
    has_txt: false,
    raw_size: data ? data.length : 0,
    resource_hash: sha256Hex(data || Buffer.alloc(0)),
    record_types: [],
    malformed: false
  };

  if (!data || data.length === 0)
    return summary;

  let resource;
  try {
    resource = Resource.decode(data);
  } catch (e) {
    summary.malformed = true;
    return summary;
  }

  const nsNames = new Set();
  const glue4 = new Set();
  const glue6 = new Set();
  const synth4 = new Set();
  const synth6 = new Set();
  const recordTypes = new Set();
  const dsRecords = [];

  for (const record of resource.records) {
    const recordType = hsTypesByVal[record.type] || String(record.type).toUpperCase();
    recordTypes.add(recordType);

    switch (recordType) {
      case 'NS':
        if (record.ns)
          nsNames.add(normalizeNS(record.ns));
        break;
      case 'GLUE4':
        if (record.ns)
          nsNames.add(normalizeNS(record.ns));
        if (record.address)
          glue4.add(normalizeAddress(record.address));
        break;
      case 'GLUE6':
        if (record.ns)
          nsNames.add(normalizeNS(record.ns));
        if (record.address)
          glue6.add(normalizeAddress(record.address));
        break;
      case 'SYNTH4':
        if (record.address)
          synth4.add(normalizeAddress(record.address));
        break;
      case 'SYNTH6':
        if (record.address)
          synth6.add(normalizeAddress(record.address));
        break;
      case 'DS':
        summary.has_ds = true;
        dsRecords.push({
          keyTag: record.keyTag,
          algorithm: record.algorithm,
          digestType: record.digestType,
          digest: Buffer.isBuffer(record.digest) ? record.digest.toString('hex') : ''
        });
        break;
      case 'TXT':
        summary.has_txt = true;
        break;
    }
  }

  summary.ns_names = sorted(nsNames);
  summary.glue4 = sorted(glue4);
  summary.glue6 = sorted(glue6);
  summary.synth4 = sorted(synth4);
  summary.synth6 = sorted(synth6);
  summary.ds_records = dsRecords.sort((a, b) =>
    JSON.stringify(a).localeCompare(JSON.stringify(b)));
  summary.record_types = sorted(recordTypes);
  return summary;
}

function compactNameRow(ns, nameHash, height, network, Resource, hsTypesByVal, statesByVal) {
  return omitDefaultFields({
    name: ns.name.toString('binary'),
    name_hash: nameHash.toString('hex'),
    state: statesByVal[ns.state(height, network)],
    renewal_height: ns.renewal,
    expired: ns.isExpired(height, network),
    ...summarizeResourceData(ns.data, Resource, hsTypesByVal)
  });
}

function omitDefaultFields(row) {
  const compact = {};

  for (const [key, value] of Object.entries(row)) {
    if (Array.isArray(value) && value.length === 0)
      continue;
    if (value === false)
      continue;
    if (key === 'raw_size' && value === 0)
      continue;
    if (value === undefined || value === null || value === '')
      continue;
    compact[key] = value;
  }

  return compact;
}

class RpcClient {
  constructor(url, apiKey) {
    this.url = new URL(url);
    this.apiKey = apiKey || '';
    this.id = 0;
    this.agent = this.url.protocol === 'https:'
      ? new https.Agent({keepAlive: true, maxSockets: 1})
      : new http.Agent({keepAlive: true, maxSockets: 1});
  }

  async call(method, params = []) {
    const body = JSON.stringify({
      jsonrpc: '2.0',
      id: ++this.id,
      method,
      params
    });

    const headers = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body)
    };

    if (this.apiKey) {
      headers.Authorization = `Basic ${Buffer.from(`:${this.apiKey}`).toString('base64')}`;
    }

    const transport = this.url.protocol === 'https:' ? https : http;
    const options = {
      method: 'POST',
      protocol: this.url.protocol,
      hostname: this.url.hostname,
      port: this.url.port,
      path: `${this.url.pathname}${this.url.search}`,
      headers,
      agent: this.agent
    };

    return new Promise((resolve, reject) => {
      const req = transport.request(options, (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          if (res.statusCode < 200 || res.statusCode >= 300) {
            reject(new Error(`RPC ${method} failed with HTTP ${res.statusCode}: ${raw}`));
            return;
          }
          let data;
          try {
            data = JSON.parse(raw);
          } catch (e) {
            reject(new Error(`RPC ${method} returned invalid JSON: ${e.message}`));
            return;
          }
          if (data.error) {
            reject(new Error(`RPC ${method} error: ${JSON.stringify(data.error)}`));
            return;
          }
          resolve(data.result);
        });
      });

      req.on('error', reject);
      req.write(body);
      req.end();
    });
  }

  close() {
    this.agent.destroy();
  }
}

function itemBuffer(covenant, index) {
  if (!covenant || !Array.isArray(covenant.items) || index >= covenant.items.length)
    return Buffer.alloc(0);
  const item = covenant.items[index];
  if (typeof item !== 'string')
    return Buffer.alloc(0);
  return Buffer.from(item, 'hex');
}

function itemU32(covenant, index) {
  const item = itemBuffer(covenant, index);
  if (item.length < 4)
    return 0;
  return item.readUInt32LE(0);
}

function itemU8(covenant, index) {
  const item = itemBuffer(covenant, index);
  if (item.length < 1)
    return 0;
  return item.readUInt8(0);
}

function covenantAction(covenant, typesByVal) {
  if (!covenant)
    return 'NONE';
  if (typeof covenant.action === 'string')
    return covenant.action.toUpperCase();
  if (Number.isSafeInteger(covenant.type))
    return String(typesByVal[covenant.type] || 'NONE').toUpperCase();
  return 'NONE';
}

function covenantNameHash(covenant) {
  const hash = itemBuffer(covenant, 0);
  if (hash.length !== 32)
    return null;
  return hash;
}

function outpoint(tx, index, Outpoint) {
  const hashHex = typeof tx.txid === 'string' ? tx.txid : tx.hash;
  const hash = typeof hashHex === 'string' && hashHex.length === 64
    ? Buffer.from(hashHex, 'hex')
    : Buffer.alloc(32, 1);
  return new Outpoint(hash, index >>> 0);
}

function outputValue(output) {
  const value = Number(output && output.value);
  if (!Number.isFinite(value) || value <= 0)
    return 0;
  return Math.round(value * 1e6);
}

function ensureNameState(states, nameHash, nameBuffer, height, NameState) {
  const key = nameHash.toString('hex');
  let ns = states.get(key);

  if (!ns) {
    ns = new NameState();
    ns.nameHash = nameHash;
    if (nameBuffer && nameBuffer.length > 0)
      ns.set(nameBuffer, height);
    states.set(key, ns);
    return ns;
  }

  if (ns.name.length === 0 && nameBuffer && nameBuffer.length > 0)
    ns.set(nameBuffer, height);

  return ns;
}

function applyCovenant(states, tx, output, height, network, NameState, Outpoint, typesByVal) {
  const covenant = output.covenant || {};
  const action = covenantAction(covenant, typesByVal);

  if (action === 'NONE' || action === 'BID' || action === 'REDEEM')
    return null;

  const nameHash = covenantNameHash(covenant);
  if (!nameHash)
    return null;

  const nameBuffer = action === 'CLAIM' || action === 'OPEN'
    ? itemBuffer(covenant, 2)
    : null;
  const ns = ensureNameState(states, nameHash, nameBuffer, height, NameState);

  ns.maybeExpire(height, network);

  const owner = outpoint(tx, output.n || 0, Outpoint);
  const value = outputValue(output);

  switch (action) {
    case 'CLAIM': {
      const flags = itemU8(covenant, 3);
      const weak = (flags & 1) !== 0;
      const claimed = itemU32(covenant, 5);
      ns.setHeight(height);
      ns.setRenewal(height);
      ns.setClaimed(claimed);
      ns.setValue(0);
      ns.setOwner(owner);
      ns.setHighest(0);
      ns.setWeak(weak);
      break;
    }
    case 'OPEN':
      break;
    case 'REVEAL':
      if (ns.owner.isNull() || value > ns.highest) {
        ns.setValue(ns.highest);
        ns.setOwner(owner);
        ns.setHighest(value);
      } else if (value > ns.value) {
        ns.setValue(value);
      }
      break;
    case 'REGISTER': {
      const data = itemBuffer(covenant, 2);
      ns.setRegistered(true);
      ns.setOwner(owner);
      if (data.length > 0)
        ns.setData(data);
      ns.setRenewal(height);
      break;
    }
    case 'UPDATE': {
      const data = itemBuffer(covenant, 2);
      ns.setOwner(owner);
      if (data.length > 0)
        ns.setData(data);
      ns.setTransfer(0);
      break;
    }
    case 'RENEW':
      ns.setOwner(owner);
      ns.setTransfer(0);
      ns.setRenewal(height);
      ns.setRenewals(ns.renewals + 1);
      break;
    case 'TRANSFER':
      ns.setOwner(owner);
      ns.setTransfer(height);
      break;
    case 'FINALIZE': {
      const flags = itemU8(covenant, 3);
      const claimed = itemU32(covenant, 4);
      const renewals = itemU32(covenant, 5);
      ns.setWeak((flags & 1) !== 0);
      ns.setClaimed(claimed);
      ns.setRenewals(renewals + 1);
      ns.setOwner(owner);
      ns.setTransfer(0);
      ns.setRenewal(height);
      break;
    }
    case 'REVOKE':
      ns.setRevoked(height);
      ns.setTransfer(0);
      ns.setData(null);
      break;
    default:
      return null;
  }

  ns.clear();
  return ns.name.length > 0 ? ns.name.toString('binary') : nameHash.toString('hex');
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const hsdRoot = discoverHsdRoot();
  const pkg = JSON.parse(fs.readFileSync(path.join(hsdRoot, 'package.json'), 'utf8'));

  const NameState = hsdRequire(hsdRoot, 'lib/covenants/namestate');
  const Outpoint = hsdRequire(hsdRoot, 'lib/primitives/outpoint');
  const Network = hsdRequire(hsdRoot, 'lib/protocol/network');
  const covenantRules = hsdRequire(hsdRoot, 'lib/covenants/rules');
  const {Resource} = hsdRequire(hsdRoot, 'lib/dns/resource');
  const {hsTypesByVal} = hsdRequire(hsdRoot, 'lib/dns/common');

  const network = Network.get(args.network);
  const rpc = new RpcClient(args.rpcUrl, args.apiKey);
  const states = new Map();
  const recentHistory = [];
  const started = Date.now();
  let processed = 0;
  let resourceDecodeErrors = 0;
  let nameCovenants = 0;

  fs.mkdirSync(path.dirname(args.out), {recursive: true});
  const tmpOut = `${args.out}.tmp-${process.pid}`;
  const stream = fs.createWriteStream(tmpOut, {encoding: 'utf8', flags: 'wx'});

  try {
    const info = await rpc.call('getblockchaininfo', []);
    const currentHeight = Number(info.blocks || info.height || 0);
    let toHeight = args.toHeight === null ? currentHeight : Math.min(args.toHeight, currentHeight);

    if (args.limitBlocks !== null)
      toHeight = Math.min(toHeight, args.fromHeight + args.limitBlocks - 1);

    if (args.fromHeight > toHeight)
      throw new Error(`from-height ${args.fromHeight} is above to-height ${toHeight}`);

    const tipHash = toHeight === currentHeight && info.bestblockhash
      ? String(info.bestblockhash)
      : String(await rpc.call('getblockhash', [toHeight]));

    await writeJsonLine(stream, {
      snapshot_meta: {
        height: toHeight,
        tip_hash: tipHash,
        chain: String(info.chain || network.type),
        hsd_version: pkg.version || 'unknown',
        source: 'hsd_nameonly_rpc_compact_experimental',
        export_format: 'compact_summary_v1',
        experimental: true,
        partial_replay: args.fromHeight !== 0,
        from_height: args.fromHeight,
        current_hsd_height: currentHeight
      }
    });

    for (let height = args.fromHeight; height <= toHeight; height++) {
      const block = await rpc.call('getblockbyheight', [height, true, true]);
      const changedNames = new Set();

      for (const tx of block.tx || []) {
        for (const output of tx.vout || tx.outputs || []) {
          const action = covenantAction(output.covenant, covenantRules.typesByVal);
          if (action !== 'NONE')
            nameCovenants += 1;
          const changed = applyCovenant(
            states,
            tx,
            output,
            height,
            network,
            NameState,
            Outpoint,
            covenantRules.typesByVal
          );
          if (changed)
            changedNames.add(changed);
        }
      }

      if (args.reorgWindow > 0) {
        recentHistory.push({
          height,
          block_hash: block.hash,
          changed_names: Array.from(changedNames).sort()
        });
        while (recentHistory.length > args.reorgWindow)
          recentHistory.shift();
      }

      processed += 1;
      if (args.progress > 0 && processed % args.progress === 0) {
        const elapsed = Math.max(0.001, (Date.now() - started) / 1000);
        const rate = processed / elapsed;
        console.error(
          `replayed ${processed} blocks through height ${height} `
          + `(${rate.toFixed(2)} blocks/sec, names=${states.size})`
        );
      }
    }

    for (const item of recentHistory)
      await writeJsonLine(stream, {block_history: item});

    const rows = Array.from(states.values())
      .filter((ns) => ns.name.length > 0)
      .sort((a, b) => a.name.compare(b.name));

    for (const ns of rows) {
      const compact = compactNameRow(
        ns,
        ns.nameHash,
        toHeight,
        network,
        Resource,
        hsTypesByVal,
        NameState.statesByVal
      );
      if (compact.malformed)
        resourceDecodeErrors += 1;
      await writeJsonLine(stream, {compact_name: compact});
    }

    await closeStream(stream);
    fs.renameSync(tmpOut, args.out);

    const elapsed = Math.max(0.001, (Date.now() - started) / 1000);
    console.error(
      `name-only replay exported ${rows.length} names to ${args.out} `
      + `at height ${toHeight} (${tipHash}); `
      + `${processed} blocks in ${elapsed.toFixed(2)}s `
      + `(${(processed / elapsed).toFixed(2)} blocks/sec); `
      + `name covenants=${nameCovenants}`
    );
    if (resourceDecodeErrors > 0)
      console.error(`resource decode errors: ${resourceDecodeErrors}`);
  } catch (e) {
    stream.destroy();
    fs.rmSync(tmpOut, {force: true});
    throw e;
  } finally {
    rpc.close();
  }
}

main().catch((e) => {
  console.error(e.stack || e.message);
  process.exit(1);
});
