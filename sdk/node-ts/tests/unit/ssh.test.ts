import { describe, expect, it } from "vitest";
import {
  sshClientOptionsToNapi,
  sshServerOptionsToNapi,
} from "../../dist/ssh.js";

describe("SSH inactivity timeout options", () => {
  it("preserves client timeout values, including zero", () => {
    expect(sshClientOptionsToNapi(undefined)).toBeUndefined();
    expect(
      sshClientOptionsToNapi({ inactivityTimeoutSecs: 30 }),
    ).toMatchObject({ inactivityTimeoutSecs: 30 });
    expect(
      sshClientOptionsToNapi({ inactivityTimeoutSecs: 0 }),
    ).toMatchObject({ inactivityTimeoutSecs: 0 });
  });

  it("preserves server timeout values, including zero", () => {
    expect(sshServerOptionsToNapi(undefined)).toBeUndefined();
    expect(
      sshServerOptionsToNapi({ inactivityTimeoutSecs: 30 }),
    ).toMatchObject({ inactivityTimeoutSecs: 30 });
    expect(
      sshServerOptionsToNapi({ inactivityTimeoutSecs: 0 }),
    ).toMatchObject({ inactivityTimeoutSecs: 0 });
  });

  it("rejects client timeout values outside the native seconds range", () => {
    for (const inactivityTimeoutSecs of [-1, 1.5, Number.NaN, 0x1_0000_0000]) {
      expect(() => sshClientOptionsToNapi({ inactivityTimeoutSecs })).toThrow(
        /integer between 0 and 4294967295/,
      );
    }
  });

  it("rejects invalid server timeout values", () => {
    expect(() =>
      sshServerOptionsToNapi({ inactivityTimeoutSecs: Number.POSITIVE_INFINITY }),
    ).toThrow(/integer between 0 and 4294967295/);
  });
});
