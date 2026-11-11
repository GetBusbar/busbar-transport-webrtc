// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const html = readFileSync(process.env.WEBRTC_TEST_PAGE || new URL("./index.html", import.meta.url), "utf8");
const script = html.split("<script>")[1].split("</script>")[0];

async function closeCell(receiptStatus) {
  let channelClosed = false;
  let receiptRequests = 0;
  class Peer {
    constructor() {
      this.connectionState = "connected";
      this.localDescription = { sdp: "v=0\r\n" };
    }
    createDataChannel() { return { close() { channelClosed = true; } }; }
    async createOffer() { return this.localDescription; }
    async setLocalDescription() {}
    async setRemoteDescription() {}
    close() { this.connectionState = "closed"; }
  }
  const context = vm.createContext({
    window: {},
    RTCPeerConnection: Peer,
    fetch: async (url) => {
      if (url === "/offer") {
        return { status: 201, text: async () => "v=0\r\n", headers: { get: () => "/closed/7" } };
      }
      assert.equal(url, "/closed/7");
      receiptRequests++;
      return { status: receiptStatus };
    },
  });
  vm.runInContext(script, context);
  vm.runInContext("capture = async () => {}; gathered = async () => {}; gradeEcho = async () => {}; waitFor = async (check) => Boolean(await check());", context);
  const cells = await context.window.runCell();
  return { cells, channelClosed, receiptRequests };
}

test("local browser closure cannot pass without the subject's END receipt", async () => {
  const { cells } = await closeCell(409);
  assert.equal(cells.close.pass, false);
});

test("subject END receipt passes after requesting data-channel closure", async () => {
  const { cells, channelClosed, receiptRequests } = await closeCell(200);
  assert.equal(cells.close.pass, true);
  assert.equal(channelClosed, true);
  assert.equal(receiptRequests, 1);
});


test("failed ICE exposes candidate diagnostics without SDP credentials", async () => {
  const context = vm.createContext({ window: {} });
  vm.runInContext(script, context);
  const peer = {
    connectionState: "failed", iceConnectionState: "failed", iceGatheringState: "complete",
    localDescription: { sdp: "a=ice-pwd:must-not-appear" },
    getStats: async () => new Map([["candidate", {
      type: "local-candidate", candidateType: "host", protocol: "udp", address: "127.0.0.1", port: 12345,
      usernameFragment: "must-not-appear",
    }]]),
  };
  const detail = await context.connectionFailure(peer);
  assert.match(detail, /ice failed, gathering complete/);
  assert.match(detail, /local-candidate\/host\/udp\/127.0.0.1\/12345/);
  assert.doesNotMatch(detail, /must-not-appear/);
});

test("a diagnostic error does not replace the original connection failure", async () => {
  const context = vm.createContext({ window: {} });
  vm.runInContext(script, context);
  const detail = await context.connectionFailure({
    connectionState: "failed", iceConnectionState: "failed", iceGatheringState: "complete",
    getStats: async () => { throw Error("stats unavailable"); },
  });
  assert.match(detail, /^connectionState failed/);
  assert.match(detail, /candidate diagnostics unavailable/);
});
