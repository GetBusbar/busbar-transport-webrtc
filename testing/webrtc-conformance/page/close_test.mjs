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
