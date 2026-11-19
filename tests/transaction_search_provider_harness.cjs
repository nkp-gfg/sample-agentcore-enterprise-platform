"use strict";

/**
 * Runs the Transaction Search provider Lambda that a synth wrote to disk.
 *
 * https.request and http.request are replaced with in-memory stand-ins before
 * the handler (and the AWS SDK it loads) run, so nothing is sent to the network.
 * The stand-in records the request the SDK serialized and returns an empty 200.
 */

const http = require("http");
const https = require("https");
const { EventEmitter } = require("events");
const { Readable } = require("stream");

const calls = [];

function fakeRequest(protocol, options, callback) {
  const req = new EventEmitter();
  const chunks = [];
  req.method = options.method;
  req.path = options.path;
  req.host = options.host || options.hostname;
  req.protocol = protocol;
  req.setTimeout = () => req;
  req.setHeader = () => req;
  req.getHeader = () => undefined;
  req.removeHeader = () => req;
  req.destroy = () => {
    req.emit("close");
    return req;
  };
  req.abort = () => req.destroy();
  req.write = (chunk) => {
    if (chunk) chunks.push(Buffer.from(chunk));
    return true;
  };
  req.end = (chunk) => {
    if (chunk) chunks.push(Buffer.from(chunk));
    const headers = options.headers || {};
    const target =
      headers["X-Amz-Target"] ||
      headers["x-amz-target"] ||
      (typeof headers.get === "function"
        ? headers.get("x-amz-target")
        : undefined);
    calls.push({
      protocol,
      host: options.host || options.hostname || "",
      method: options.method || "GET",
      path: options.path || "/",
      target: target || "",
      body: Buffer.concat(chunks).toString("utf8"),
    });
    const res = Readable.from([Buffer.from("{}")]);
    res.statusCode = 200;
    res.statusMessage = "OK";
    res.headers = {
      "content-type": "application/json",
      "x-amzn-requestid": "test",
    };
    if (typeof callback === "function") callback(res);
    req.emit("response", res);
    return req;
  };
  const socket = new EventEmitter();
  socket.connecting = false;
  socket.setTimeout = () => socket;
  socket.setKeepAlive = () => socket;
  socket.destroy = () => socket;
  socket.removeListener = () => socket;
  process.nextTick(() => req.emit("socket", socket));
  return req;
}

https.request = function request(options, callback) {
  return fakeRequest("https", options, callback);
};
http.request = function request(options, callback) {
  return fakeRequest("http", options, callback);
};

function readStdin() {
  return new Promise((resolve, reject) => {
    const chunks = [];
    process.stdin.on("data", (chunk) => chunks.push(chunk));
    process.stdin.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    process.stdin.on("error", reject);
  });
}

function eventFor(requestType, call) {
  const encoded = JSON.stringify(call);
  const properties = { InstallLatestAwsSdk: "false" };
  properties[requestType] = encoded;
  return {
    RequestType: requestType,
    ServiceToken: "arn:aws:lambda:us-east-1:111111111111:function:provider",
    ResponseURL: "https://cloudformation-custom-resource-response.invalid/wait",
    StackId: "arn:aws:cloudformation:us-east-1:111111111111:stack/obs/guid",
    RequestId: "req-1",
    LogicalResourceId: "TraceSegmentDestination",
    PhysicalResourceId: "plat-dev-trace-destination",
    ResourceProperties: properties,
  };
}

async function main() {
  const handlerPath = process.argv[2];
  const cases = JSON.parse(await readStdin());
  console.log = () => {};
  console.info = () => {};
  console.debug = () => {};
  const { handler } = require(handlerPath);
  const results = [];
  for (const item of cases) {
    const before = calls.length;
    let error = null;
    try {
      await handler(eventFor(item.requestType, item.call), {
        logStreamName: "stream",
      });
    } catch (err) {
      error = err && err.message ? err.message : String(err);
    }
    const made = calls.slice(before).filter((call) => {
      const host = String(call.host || "");
      return !host.includes("cloudformation-custom-resource-response");
    });
    results.push({ name: item.name, error, calls: made });
  }
  process.stdout.write(JSON.stringify(results));
}

main().catch((err) => {
  process.stderr.write(String(err && err.stack ? err.stack : err));
  process.exit(1);
});
