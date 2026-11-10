#!/usr/bin/env node
// node tools/lookup/cli.mjs <account> [--suite S] [--json] [--rpc URL]
// Exit code: 0 = a published result applies to this guard and it held; 1 = any other answer;
//            2 = bad usage or the lookup could not finish (never read as a pass).
import { lookup, formatAnswer, STATUS } from "./arena-lookup.mjs";

const USAGE = "usage: node tools/lookup/cli.mjs <account> [--suite S] [--json] [--rpc URL]";

function parse(argv) {
  const a = { account: null, suite: undefined, json: false, rpcUrl: undefined };
  for (let i = 0; i < argv.length; i++) {
    const x = argv[i];
    if (x === "--json") a.json = true;
    else if (x === "--suite" || x === "--rpc") {
      const v = argv[++i];
      if (!v) throw new Error(`${x} needs a value`);
      if (x === "--suite") a.suite = v;
      else a.rpcUrl = v;
    } else if (x === "-h" || x === "--help") throw new Error("help");
    else if (x.startsWith("-")) throw new Error(`unknown option ${x}`);
    else if (a.account) throw new Error("give one account");
    else a.account = x;
  }
  if (!a.account) throw new Error("give an account");
  return a;
}

let args;
try {
  args = parse(process.argv.slice(2));
} catch (e) {
  console.error(e.message === "help" ? USAGE : `${e.message}\n${USAGE}`);
  process.exit(2);
}

const answer = await lookup(args.account, { suite: args.suite, rpcUrl: args.rpcUrl });
console.log(args.json ? JSON.stringify(answer, null, 2) : formatAnswer(answer));
process.exit(answer.status === STATUS.HELD ? 0 : answer.status === STATUS.ERROR || answer.status === STATUS.BAD_INPUT ? 2 : 1);
