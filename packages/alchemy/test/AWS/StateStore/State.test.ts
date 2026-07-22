import * as AWS from "@/AWS";
import { makeS3State } from "@/AWS";
import { AWSEnvironment } from "@/AWS/Environment.ts";
import { createStateBucketName } from "@/AWS/StateStore/State.ts";
import type { ResourceState, StateService } from "@/State";
import * as Test from "@/Test/Alchemy";
import * as s3 from "@distilled.cloud/aws/s3";
import { expect } from "alchemy-test";
import * as Effect from "effect/Effect";
import * as Redacted from "effect/Redacted";
import * as Result from "effect/Result";
import * as Stream from "effect/Stream";

const { test } = Test.make({ providers: AWS.providers() });

const STACK = "S3StateStoreTestStack";

/**
 * Guaranteed out-of-band cleanup: `deleteStack` is idempotent (list +
 * batched delete), and `Effect.orDie` collapses the finalizer's error
 * channel to `never` so it is a valid `Effect.ensuring` finalizer.
 * Every test pre-cleans AND finalizes with this so a failing assertion
 * can never leave state objects behind in the bucket.
 */
const cleanStage = (state: StateService, stage: string) =>
  state.deleteStack({ stack: STACK, stage }).pipe(Effect.orDie);

const resource = (fqn: string, attr: Record<string, unknown>): ResourceState =>
  ({
    resourceType: "test:resource",
    namespace: undefined,
    fqn,
    logicalId: fqn,
    instanceId: `instance-${fqn}`,
    providerVersion: 1,
    status: "created",
    downstream: [],
    bindings: [],
    props: {},
    attr,
  }) as ResourceState;

test.provider(
  "set/get/list/delete round-trips state through S3",
  () =>
    Effect.gen(function* () {
      const state = yield* makeS3State({ prefix: "test-state" });
      const stage = "round-trip";

      // start from a clean slate (idempotent)
      yield* state.deleteStack({ stack: STACK, stage });

      yield* Effect.gen(function* () {
        const a = resource("Parent/ResourceA", { value: "a" });
        const b = resource("ResourceB", { value: "b" });

        yield* state.set({ stack: STACK, stage, fqn: a.fqn, value: a });
        yield* state.set({ stack: STACK, stage, fqn: b.fqn, value: b });

        expect(yield* state.get({ stack: STACK, stage, fqn: a.fqn })).toEqual(
          a,
        );
        expect(
          yield* state.get({ stack: STACK, stage, fqn: "does-not-exist" }),
        ).toBeUndefined();

        const fqns = yield* state.list({ stack: STACK, stage });
        expect([...fqns].sort()).toEqual(["Parent/ResourceA", "ResourceB"]);

        expect(yield* state.listStacks()).toContain(STACK);
        expect(yield* state.listStages(STACK)).toContain(stage);

        yield* state.delete({ stack: STACK, stage, fqn: a.fqn });
        expect(
          yield* state.get({ stack: STACK, stage, fqn: a.fqn }),
        ).toBeUndefined();
        // deleting a missing resource is a no-op
        yield* state.delete({ stack: STACK, stage, fqn: a.fqn });

        yield* state.deleteStack({ stack: STACK, stage });
        expect(yield* state.list({ stack: STACK, stage })).toEqual([]);
      }).pipe(Effect.ensuring(cleanStage(state, stage)));
    }),
  { timeout: 120_000 },
);

test.provider(
  "stack outputs are stored separately from resources",
  () =>
    Effect.gen(function* () {
      const state = yield* makeS3State({ prefix: "test-state" });
      const stage = "outputs";

      yield* state.deleteStack({ stack: STACK, stage });

      yield* Effect.gen(function* () {
        expect(yield* state.getOutput({ stack: STACK, stage })).toBeUndefined();

        yield* state.setOutput({
          stack: STACK,
          stage,
          value: { url: "https://example.com" },
        });
        expect(yield* state.getOutput({ stack: STACK, stage })).toEqual({
          url: "https://example.com",
        });

        // the output bookkeeping object must not leak into list()
        expect(yield* state.list({ stack: STACK, stage })).toEqual([]);

        yield* state.deleteStack({ stack: STACK, stage });
        expect(yield* state.getOutput({ stack: STACK, stage })).toBeUndefined();
      }).pipe(Effect.ensuring(cleanStage(state, stage)));
    }),
  { timeout: 120_000 },
);

/**
 * Deterministic parameter name for the test key. Deliberately left in
 * place across runs (standard-tier SecureString parameters are free)
 * so every run reuses the same key, mirroring real usage.
 */
const SECRETS_PARAM = "/alchemy/test/state-store/secrets-key";

/** Read the raw (undecrypted) state object bytes out of the bucket. */
const readRawObject = (key: string) =>
  Effect.gen(function* () {
    const { accountId, region } = yield* AWSEnvironment.current;
    const bucket = createStateBucketName(accountId, region);
    const result = yield* s3.getObject({ Bucket: bucket, Key: key });
    return result.Body === undefined
      ? ""
      : yield* Stream.mkString(Stream.decodeText(result.Body));
  });

test.provider(
  "ssm secrets tier encrypts Redacted values at rest",
  () =>
    Effect.gen(function* () {
      const state = yield* makeS3State({
        prefix: "test-state",
        secrets: { kind: "ssm", parameterName: SECRETS_PARAM },
      });
      const stage = "secrets-ssm";

      yield* state.deleteStack({ stack: STACK, stage });

      yield* Effect.gen(function* () {
        const secret = "s3cret-token-value";
        const a = resource("SecretResource", {
          token: Redacted.make(secret),
          plain: "visible",
        });
        yield* state.set({ stack: STACK, stage, fqn: a.fqn, value: a });

        // Round-trip: the Redacted value survives with its wrapper.
        const got = (yield* state.get({
          stack: STACK,
          stage,
          fqn: a.fqn,
        })) as ResourceState & { attr: { token: unknown; plain: string } };
        expect(Redacted.isRedacted(got.attr.token)).toBe(true);
        expect(
          Redacted.value(got.attr.token as Redacted.Redacted<string>),
        ).toBe(secret);
        expect(got.attr.plain).toBe("visible");

        // Out-of-band: the raw S3 object holds ciphertext for the
        // secret while the rest of the state stays readable JSON.
        const raw = yield* readRawObject(
          `test-state/${STACK}/${stage}/SecretResource.json`,
        );
        expect(raw).not.toContain(secret);
        expect(raw).not.toContain("__redacted__");
        expect(raw).toContain("__secret__");
        expect(raw).toContain("visible");

        // Legacy plaintext entries written before encryption was
        // enabled still read through the encrypting store unchanged.
        const plaintextStore = yield* makeS3State({ prefix: "test-state" });
        const b = resource("LegacyResource", { token: Redacted.make(secret) });
        yield* plaintextStore.set({
          stack: STACK,
          stage,
          fqn: b.fqn,
          value: b,
        });
        const legacy = (yield* state.get({
          stack: STACK,
          stage,
          fqn: b.fqn,
        })) as ResourceState & { attr: { token: Redacted.Redacted<string> } };
        expect(Redacted.value(legacy.attr.token)).toBe(secret);

        // A plaintext-configured store refuses to surface ciphertext.
        const failed = yield* Effect.result(
          plaintextStore.get({ stack: STACK, stage, fqn: a.fqn }),
        );
        expect(Result.isFailure(failed)).toBe(true);
      }).pipe(Effect.ensuring(cleanStage(state, stage)));
    }),
  { timeout: 120_000 },
);

/**
 * KMS lifecycle is gated on a caller-supplied key: auto-provisioning a
 * customer-managed key in tests would accumulate $1/month CMKs that
 * take 7+ days of scheduled deletion to reclaim. Set
 * `AWS_TEST_STATE_KMS_KEY_ID` (a key ID, ARN, or alias) to run it.
 */
test.provider.skipIf(!process.env.AWS_TEST_STATE_KMS_KEY_ID)(
  "kms secrets tier encrypts Redacted values at rest",
  () =>
    Effect.gen(function* () {
      const state = yield* makeS3State({
        prefix: "test-state",
        secrets: {
          kind: "kms",
          keyId: process.env.AWS_TEST_STATE_KMS_KEY_ID,
        },
      });
      const stage = "secrets-kms";

      yield* state.deleteStack({ stack: STACK, stage });

      yield* Effect.gen(function* () {
        const secret = "kms-s3cret-token-value";
        const a = resource("SecretResource", { token: Redacted.make(secret) });
        yield* state.set({ stack: STACK, stage, fqn: a.fqn, value: a });

        const got = (yield* state.get({
          stack: STACK,
          stage,
          fqn: a.fqn,
        })) as ResourceState & { attr: { token: Redacted.Redacted<string> } };
        expect(Redacted.value(got.attr.token)).toBe(secret);

        const raw = yield* readRawObject(
          `test-state/${STACK}/${stage}/SecretResource.json`,
        );
        expect(raw).not.toContain(secret);
        expect(raw).toContain("__secret__");
      }).pipe(Effect.ensuring(cleanStage(state, stage)));
    }),
  { timeout: 120_000 },
);

test.provider(
  "getReplacedResources returns only replaced resources",
  () =>
    Effect.gen(function* () {
      const state = yield* makeS3State({ prefix: "test-state" });
      const stage = "replaced";

      yield* state.deleteStack({ stack: STACK, stage });

      yield* Effect.gen(function* () {
        const created = resource("Created", { value: "created" });
        const replaced = {
          ...resource("Replaced", { value: "replaced" }),
          status: "replaced",
        } as ResourceState;

        yield* state.set({
          stack: STACK,
          stage,
          fqn: created.fqn,
          value: created,
        });
        yield* state.set({
          stack: STACK,
          stage,
          fqn: replaced.fqn,
          value: replaced,
        });

        const result = yield* state.getReplacedResources({
          stack: STACK,
          stage,
        });
        expect(result.map((r) => r.fqn)).toEqual(["Replaced"]);
      }).pipe(Effect.ensuring(cleanStage(state, stage)));
    }),
  { timeout: 120_000 },
);
