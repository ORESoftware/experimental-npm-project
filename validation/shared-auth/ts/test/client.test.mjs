import assert from "node:assert/strict";
import test from "node:test";
import {
  MissingServiceCredentialError,
  SharedAuthClient,
} from "../dist/index.js";

test("protected introspection fails before fetch when unconfigured", async () => {
  let calls = 0;
  const client = new SharedAuthClient("https://gateway.example/shared-auth", {
    fetch: async () => {
      calls += 1;
      throw new Error("fetch must not be called");
    },
  });

  await assert.rejects(
    client.introspect("ore-token"),
    MissingServiceCredentialError,
  );
  assert.equal(calls, 0);

  client.withServiceCredential("service-secret").withoutServiceCredential();
  await assert.rejects(
    client.introspect("ore-token"),
    MissingServiceCredentialError,
  );
  assert.equal(calls, 0);
});

test("configured introspection sends only the service bearer", async () => {
  let authorization;
  const client = new SharedAuthClient("https://gateway.example/shared-auth", {
    serviceCredential: "service-secret",
    fetch: async (_url, init) => {
      authorization = new Headers(init.headers).get("authorization");
      return Response.json({ active: false });
    },
  });
  const result = await client.introspect("ore-token");
  assert.equal(result.active, false);
  assert.equal(authorization, "Bearer service-secret");
});
