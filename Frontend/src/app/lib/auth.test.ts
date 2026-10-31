import { beforeEach, describe, expect, it } from "vitest";

import { clearAuthSession, getAuthSession, isAuthenticated, setAuthSession } from "./auth";

const STORAGE_KEY = "aeroledger-auth-session";

/** Build a JWT with the given payload. The signature is never verified here. */
function jwt(payload: Record<string, unknown>, segments = 3): string {
  const b64 = (obj: unknown) =>
    btoa(JSON.stringify(obj)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const parts = [b64({ alg: "HS256", typ: "JWT" }), b64(payload), "signature"];
  while (parts.length < segments) parts.push("extra");
  return parts.join(".");
}

function session(token: string) {
  return { id: "user-1", email: "a@example.com", name: "A", role: "user", token };
}

const future = Math.floor(Date.now() / 1000) + 3600;
const past = Math.floor(Date.now() / 1000) - 3600;

beforeEach(() => {
  window.localStorage.clear();
});

describe("getAuthSession", () => {
  it("returns a session whose token has not expired", () => {
    setAuthSession(session(jwt({ exp: future })));
    expect(getAuthSession()?.email).toBe("a@example.com");
    expect(isAuthenticated()).toBe(true);
  });

  /**
   * The security-relevant one. An expired token must not keep the user looking
   * signed in: every request would be rejected by the backend anyway, and a UI
   * that still shows an authenticated state hides that.
   */
  it("rejects an expired token and clears it from storage", () => {
    setAuthSession(session(jwt({ exp: past })));
    expect(getAuthSession()).toBeNull();
    expect(window.localStorage.getItem(STORAGE_KEY)).toBeNull();
  });

  it("treats a token with no exp claim as non-expiring here", () => {
    // Expiry is the backend's call; the client only short-circuits the obvious.
    setAuthSession(session(jwt({ sub: "user-1" })));
    expect(getAuthSession()).not.toBeNull();
  });

  /**
   * A JWT is exactly three segments. A four-segment token is not a JWT, and its
   * payload must not be decoded or trusted — the structural check is what stops
   * an attacker-shaped token having its claims read at all.
   */
  it("does not decode a token with more than three segments", () => {
    setAuthSession(session(jwt({ exp: past }, 4)));
    // Undecodable, so the client defers to the backend rather than reading
    // claims out of a malformed token.
    expect(getAuthSession()).not.toBeNull();
  });

  it("does not decode a token with fewer than three segments", () => {
    setAuthSession(session("not.ajwt"));
    expect(getAuthSession()).not.toBeNull();
  });

  it("survives a token that is not base64 at all", () => {
    setAuthSession(session("%%%.%%%.%%%"));
    expect(() => getAuthSession()).not.toThrow();
  });

  it("clears a stored session missing required fields", () => {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify({ token: jwt({ exp: future }) }));
    expect(getAuthSession()).toBeNull();
    expect(window.localStorage.getItem(STORAGE_KEY)).toBeNull();
  });

  it("recovers from malformed stored JSON", () => {
    window.localStorage.setItem(STORAGE_KEY, "{not json");
    expect(getAuthSession()).toBeNull();
  });

  it("returns null when nothing is stored", () => {
    expect(getAuthSession()).toBeNull();
    expect(isAuthenticated()).toBe(false);
  });
});

describe("clearAuthSession", () => {
  it("removes the stored session", () => {
    setAuthSession(session(jwt({ exp: future })));
    clearAuthSession();
    expect(getAuthSession()).toBeNull();
  });
});
