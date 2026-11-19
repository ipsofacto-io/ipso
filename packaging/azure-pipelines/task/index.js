"use strict";

// A Marketplace task needs a Node handler. The check is check.sh, which is the only
// implementation, so this file reads the inputs and execs that script.
const { spawnSync } = require("child_process");
const path = require("path");

function fail(message) {
  process.stderr.write("##vso[task.logissue type=error]" + message + "\n");
  process.exit(2);
}

function input(name) {
  const value = process.env["INPUT_" + name];
  return value === undefined ? "" : value;
}

if (process.platform === "win32" || process.env.AGENT_OS === "Windows_NT") {
  fail("ipso check runs on Linux and macOS agents");
}

const temp = process.env.AGENT_TEMPDIRECTORY || process.env.IPSO_TEMP;
if (!temp) {
  fail("AGENT_TEMPDIRECTORY is not set");
}

const env = Object.assign({}, process.env, {
  IPSO_COMMAND: input("COMMAND"),
  IPSO_ARGS: input("ARGS"),
  IPSO_ENV: input("ENV"),
  IPSO_INPUT: input("INPUT"),
  IPSO_VERSION: input("VERSION") || "0.4.0",
  IPSO_CLI_PATH: input("CLI-PATH") || input("CLIPATH"),
  IPSO_TEMP: temp,
});

const result = spawnSync("bash", [path.join(__dirname, "check.sh")], {
  env: env,
  stdio: "inherit",
});
if (result.error) {
  fail("could not run the check script");
}
process.exit(result.status === null ? 1 : result.status);
