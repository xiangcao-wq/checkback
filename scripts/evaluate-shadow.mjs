import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  evaluateShadowSuite,
  evaluateVerifierGates,
  formatShadowEvaluationReport,
  parseShadowEvaluationSuite,
} from "../evaluation/shadow-evaluator.ts";

function defaultIo() {
  return {
    readFile,
    stdout(value) {
      process.stdout.write(value);
    },
    stderr(value) {
      process.stderr.write(value);
    },
  };
}

function parseArguments(args) {
  const allowedFlags = new Set(["--json", "--enforce-verifier-gates"]);
  const flags = new Set(args.filter((value) => value.startsWith("--")));
  const unknownFlags = [...flags].filter((value) => !allowedFlags.has(value));
  const positionals = args.filter((value) => !value.startsWith("--"));

  if (unknownFlags.length > 0 || positionals.length > 1) {
    throw new Error(
      "usage: evaluate-shadow.mjs [suite.json] [--json] [--enforce-verifier-gates]",
    );
  }

  return {
    json: flags.has("--json"),
    enforce: flags.has("--enforce-verifier-gates"),
    input:
      positionals.length === 1
        ? resolve(positionals[0])
        : new URL("../evaluation/fixtures/v1/synthetic.json", import.meta.url),
  };
}

function safeErrorMessage(error) {
  if (error && Array.isArray(error.issues)) {
    return error.issues
      .slice(0, 5)
      .map((issue) => {
        const path = Array.isArray(issue.path) ? issue.path.join(".") : "suite";
        return path + ": " + issue.message;
      })
      .join("; ");
  }
  if (error instanceof SyntaxError) return "input is not valid JSON";
  if (error instanceof Error && error.message.startsWith("usage:")) {
    return error.message;
  }
  return "evaluation failed";
}

export async function runCli(args, io = defaultIo()) {
  try {
    const options = parseArguments(args);
    const input = await io.readFile(options.input, "utf8");
    const suite = parseShadowEvaluationSuite(JSON.parse(input));
    const metrics = await evaluateShadowSuite(suite);
    const gates = evaluateVerifierGates(metrics);

    if (options.json) {
      io.stdout(JSON.stringify({ metrics, gates }, null, 2) + "\n");
    } else {
      io.stdout(formatShadowEvaluationReport(metrics, gates) + "\n");
    }

    return options.enforce && !gates.verifier_gate_passed ? 1 : 0;
  } catch (error) {
    io.stderr("Invalid Shadow evaluation suite: " + safeErrorMessage(error) + "\n");
    return 2;
  }
}

const directEntry =
  process.argv[1] &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url;

if (directEntry) {
  process.exitCode = await runCli(process.argv.slice(2));
}
