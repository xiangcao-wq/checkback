import { createRequire, syncBuiltinESMExports } from "node:module";

const require = createRequire(import.meta.url);
let attemptedCalls = 0;
const block = () => {
  attemptedCalls += 1;
  throw new Error(`offline_network_tripwire:${attemptedCalls}`);
};

Object.defineProperty(globalThis, "fetch", {
  configurable: false,
  enumerable: true,
  writable: false,
  value: block,
});
Object.defineProperty(globalThis, "WebSocket", {
  configurable: false,
  enumerable: true,
  writable: false,
  value: class BlockedWebSocket {
    constructor() {
      block();
    }
  },
});

const http = require("node:http");
const https = require("node:https");
const http2 = require("node:http2");
const net = require("node:net");
const tls = require("node:tls");
const dns = require("node:dns");
const dgram = require("node:dgram");

for (const client of [http, https]) {
  client.request = block;
  client.get = block;
}
http2.connect = block;
net.connect = block;
net.createConnection = block;
net.Socket.prototype.connect = block;
tls.connect = block;
for (const method of [
  "lookup",
  "resolve",
  "resolve4",
  "resolve6",
  "resolveAny",
  "resolveCaa",
  "resolveCname",
  "resolveMx",
  "resolveNaptr",
  "resolveNs",
  "resolvePtr",
  "resolveSoa",
  "resolveSrv",
  "resolveTxt",
  "reverse",
]) {
  if (typeof dns[method] === "function") dns[method] = block;
  if (typeof dns.promises?.[method] === "function") {
    dns.promises[method] = block;
  }
}
dgram.createSocket = block;
dgram.Socket.prototype.send = block;
syncBuiltinESMExports();

process.on("exit", () => {
  if (attemptedCalls !== 0) process.exitCode = 97;
});
