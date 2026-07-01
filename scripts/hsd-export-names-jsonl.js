#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const {execFileSync} = require('child_process');
const {once} = require('events');

class NullLogger {
  context() {
    return this;
  }

  info() {}
  debug() {}
  warning() {}
  error() {}
  spam() {}
  memory() {}
}

function usage() {
  return [
    'usage: hsd-export-names-jsonl.js --prefix <hsd-prefix> --out <path> [options]',
    '',
    'Options:',
    '  --network <name>  HSD network name. Default: main',
    '  --limit <n>       Export at most n names for a smoke run.',
    '  --progress <n>    Emit progress every n exported names. Default: 10000',
    '  --help            Show this help text.',
    '',
    'Environment:',
    '  HSD_MODULE_ROOT   Optional path to the installed hsd package root.',
    '  HSD_NETWORK       Default network when --network is omitted.',
  ].join('\n');
}

function parseArgs(argv) {
  const args = {
    prefix: process.env.INDEXER_HSD_PREFIX || process.env.HSD_PREFIX || '/mnt/hnscrawler/hsd',
    out: process.env.JSONL_PATH || '/mnt/hnscrawler/data/extracted_names.jsonl',
    network: process.env.HSD_NETWORK || 'main',
    limit: null,
    progress: 10000
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
      case '--prefix':
        args.prefix = next();
        break;
      case '--out':
        args.out = next();
        break;
      case '--network':
        args.network = next();
        break;
      case '--limit':
        args.limit = positiveInt('--limit', next());
        break;
      case '--progress':
        args.progress = positiveInt('--progress', next());
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

  return args;
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
        && fs.existsSync(path.join(root, 'lib', 'blockchain', 'chaindb.js'))) {
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

function hashToHex(value) {
  if (Buffer.isBuffer(value))
    return value.toString('hex');
  if (value && Buffer.isBuffer(value.hash))
    return value.hash.toString('hex');
  return String(value || '');
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

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const hsdRoot = discoverHsdRoot();
  const pkg = JSON.parse(fs.readFileSync(path.join(hsdRoot, 'package.json'), 'utf8'));

  const ChainDB = hsdRequire(hsdRoot, 'lib/blockchain/chaindb');
  const NameState = hsdRequire(hsdRoot, 'lib/covenants/namestate');
  const Network = hsdRequire(hsdRoot, 'lib/protocol/network');
  const {Resource} = hsdRequire(hsdRoot, 'lib/dns/resource');

  const chainPath = path.join(args.prefix, 'chain');
  const treePath = path.join(args.prefix, 'tree');
  if (!fs.existsSync(chainPath) || !fs.existsSync(treePath)) {
    throw new Error(
      `HSD prefix does not contain existing chain and tree directories: ${args.prefix}`
    );
  }

  const network = Network.get(args.network);
  const logger = new NullLogger();
  const db = new ChainDB({
    network,
    logger,
    blocks: null,
    prefix: args.prefix,
    location: chainPath,
    treePrefix: treePath,
    memory: false,
    maxFiles: 64,
    cacheSize: 32 << 20,
    compression: true,
    spv: false,
    prune: false,
    indexTX: false,
    indexAddress: false,
    chainMigrate: -1,
    compactTreeOnInit: false,
    compactTreeInitInterval: 10000
  });

  fs.mkdirSync(path.dirname(args.out), {recursive: true});
  const tmpOut = `${args.out}.tmp-${process.pid}`;
  const stream = fs.createWriteStream(tmpOut, {encoding: 'utf8', flags: 'wx'});

  let count = 0;
  let resourceDecodeErrors = 0;

  try {
    await db.open();
    const tip = await db.getTip();
    if (!tip)
      throw new Error('HSD chain database has no tip');

    const height = tip.height;
    const tipHash = hashToHex(tip.hash);

    await writeJsonLine(stream, {
      snapshot_meta: {
        height,
        tip_hash: tipHash,
        chain: network.type,
        hsd_version: pkg.version || 'unknown',
        source: 'hsd_chain_tree_stream'
      }
    });

    const iter = db.txn.iterator();
    while (await iter.next()) {
      const ns = NameState.decode(iter.value);
      ns.nameHash = iter.key;

      const nameInfo = ns.getJSON(height, network);
      const name = nameInfo.name;
      let resource = {records: []};

      if (ns.data && ns.data.length > 0) {
        try {
          resource = Resource.decode(ns.data).getJSON(name);
        } catch (e) {
          resourceDecodeErrors += 1;
          resource = {records: [], decode_error: e.message};
        }
      }

      await writeJsonLine(stream, {name_info: nameInfo, resource});
      count += 1;

      if (args.progress > 0 && count % args.progress === 0)
        console.error(`exported ${count} names`);

      if (args.limit !== null && count >= args.limit)
        break;
    }

    await closeStream(stream);
    fs.renameSync(tmpOut, args.out);
    console.error(`exported ${count} names to ${args.out} at height ${height} (${tipHash})`);
    if (resourceDecodeErrors > 0)
      console.error(`resource decode errors: ${resourceDecodeErrors}`);
  } catch (e) {
    stream.destroy();
    fs.rmSync(tmpOut, {force: true});
    throw e;
  } finally {
    await db.close().catch(() => {});
  }
}

main().catch((e) => {
  console.error(e.stack || e.message);
  process.exit(1);
});
