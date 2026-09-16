import { describe, expect, it } from "vitest";
import { WebSocketTransport, type WebSocketLike } from "../src/index.js";

class Socket extends EventTarget {
  binaryType: BinaryType = "blob";
  readyState = 1;
  bufferedAmount = 0;
  sent: Uint8Array[] = [];
  send(bytes: Uint8Array): void { this.sent.push(Uint8Array.from(bytes)); this.bufferedAmount += bytes.length; }
  close(): void { this.readyState = 3; this.dispatchEvent(new Event("close")); }
  message(data: unknown): void { this.dispatchEvent(new MessageEvent("message", { data })); }
  asWebSocket(): WebSocketLike { return this as unknown as WebSocketLike; }
}

describe("bounded browser byte transport", () => {
  it("preserves fragmented/coalesced message bytes and EOF boundaries", async () => {
    const socket = new Socket(), transport = new WebSocketTransport(socket.asWebSocket());
    expect(socket.binaryType).toBe("arraybuffer");
    const first = transport.read(3);
    socket.message(new Uint8Array([1, 2]).buffer);
    socket.message(new Uint8Array([3, 4, 5]));
    expect(await first).toEqual(new Uint8Array([1, 2]));
    expect(await transport.read(2)).toEqual(new Uint8Array([3, 4]));
    socket.close();
    expect(await transport.read(2)).toEqual(new Uint8Array([5]));
    expect(await transport.read(1)).toBeNull();
  });

  it("closes on byte and message queue overflow without throwing from the event callback", async () => {
    for (const options of [{ bufferedBytes: 2 }, { bufferedMessages: 1 }]) {
      const socket = new Socket(), transport = new WebSocketTransport(socket.asWebSocket(), options);
      socket.message(new Uint8Array([1, 2]));
      expect(() => socket.message(new Uint8Array([3]))).not.toThrow();
      await expect(transport.read(1)).rejects.toMatchObject({ code: "capacity" });
      expect(socket.readyState).toBe(3);
    }
  });

  it("rejects nonbinary input and wakes the pending read", async () => {
    const socket = new Socket(), transport = new WebSocketTransport(socket.asWebSocket());
    const read = expect(transport.read(1)).rejects.toMatchObject({ code: "invalid_data" });
    expect(() => socket.message("secret data must not appear in an error")).not.toThrow();
    await read;
    expect(socket.readyState).toBe(3);
  });

  it("waits for the browser write queue and wakes writes and reads on close", async () => {
    const socket = new Socket(), transport = new WebSocketTransport(socket.asWebSocket());
    let completed = false;
    const write = transport.write(new Uint8Array([1, 2])).then(() => { completed = true; });
    await new Promise(resolve => setTimeout(resolve, 10));
    expect(completed).toBe(false);
    expect(socket.sent).toEqual([new Uint8Array([1, 2])]);
    socket.bufferedAmount = 0;
    await write;
    const pendingWrite = expect(transport.write(new Uint8Array([3]))).rejects.toMatchObject({ code: "closed" });
    const pendingRead = transport.read(1);
    await transport.close();
    await pendingWrite;
    expect(await pendingRead).toBeNull();
  });
});
