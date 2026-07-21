import type { Credentials } from "@distilled.cloud/aws/Credentials";
import type { Region } from "@distilled.cloud/aws/Region";
import * as kms from "@distilled.cloud/aws/kms";
import * as ssm from "@distilled.cloud/aws/ssm";
import * as Effect from "effect/Effect";
import * as Redacted from "effect/Redacted";
import type { HttpClient } from "effect/unstable/http/HttpClient";
import crypto from "node:crypto";
import { StateStoreError } from "../../State/State.ts";
import { REDACTED_MARKER } from "../../State/StateEncoding.ts";

/**
 * How the state store persists `Redacted` secret values inside resource
 * state. Non-secret state is always stored as readable plaintext JSON;
 * this option only tiers what happens to the secret fields.
 */
export type StateSecretsOptions =
  | {
      /**
       * Secrets are stored as plaintext JSON (the historical behaviour).
       * Anyone with read access to the state bucket can read them.
       */
      readonly kind: "plaintext";
    }
  | {
      /**
       * Secrets are encrypted client-side with AES-256-GCM using a random
       * 256-bit key held in an SSM Parameter Store `SecureString`
       * parameter. The parameter is created automatically on first use
       * (free — standard tier). Reading state then requires
       * `ssm:GetParameter` on the key parameter in addition to bucket
       * read access.
       */
      readonly kind: "ssm";
      /**
       * Name of the `SecureString` parameter that holds the hex-encoded
       * 256-bit key.
       * @default "/alchemy/state-store/secrets-key"
       */
      readonly parameterName?: string;
    }
  | {
      /**
       * Each secret is encrypted via `kms:Encrypt` against a
       * customer-managed KMS key, so every decrypt is individually
       * authorized and CloudTrail-audited.
       */
      readonly kind: "kms";
      /**
       * The KMS key to use — a key ID, key ARN, alias name, or alias ARN.
       * When omitted, a customer-managed key is provisioned on first use
       * under {@link DEFAULT_KMS_ALIAS} (note: a customer-managed key
       * costs ~$1/month while it exists).
       */
      readonly keyId?: string;
    };

/**
 * JSON marker wrapping an encrypted secret in persisted state. Sits in
 * the position `encodeState` would have written a `__redacted__`
 * marker; the read path decrypts it back into one.
 */
export const SECRET_MARKER = "__secret__";

/** Alias created for the auto-provisioned KMS key. */
export const DEFAULT_KMS_ALIAS = "alias/alchemy-state-store";

/** Default name of the SSM parameter that holds the AES key. */
export const DEFAULT_SSM_PARAMETER = "/alchemy/state-store/secrets-key";

/**
 * KMS encryption context bound to every Encrypt/Decrypt call so
 * state-store ciphertext can only be decrypted as state-store
 * ciphertext (and CloudTrail entries are attributable).
 */
const ENCRYPTION_CONTEXT = { "alchemy:purpose": "state-store-secret" };

/** `kms:Encrypt` rejects plaintext larger than 4096 bytes. */
const KMS_MAX_PLAINTEXT_BYTES = 4096;

const AES_ALG = "aes-256-gcm" as const;
const KMS_ALG = "kms" as const;
const AES_IV_BYTES = 12;
const AES_TAG_BYTES = 16;
const AES_KEY_BYTES = 32;

interface SecretEnvelope {
  readonly v: 1;
  readonly alg: typeof AES_ALG | typeof KMS_ALG;
  /**
   * Base64 ciphertext. For `aes-256-gcm` it is framed as
   * `iv || ciphertext || tag`; for `kms` it is the raw
   * `CiphertextBlob` (which embeds the key id).
   */
  readonly ct: string;
}

const isSecretEnvelope = (value: unknown): value is SecretEnvelope =>
  value !== null &&
  typeof value === "object" &&
  (value as SecretEnvelope).v === 1 &&
  ((value as SecretEnvelope).alg === AES_ALG ||
    (value as SecretEnvelope).alg === KMS_ALG) &&
  typeof (value as SecretEnvelope).ct === "string";

/**
 * Encrypts/decrypts a single secret's JSON text. Methods are
 * self-contained (`R = never`) — AWS context is captured at
 * construction so the codec can back `StateService` methods directly.
 */
export interface SecretsCodec {
  readonly encrypt: (
    plaintext: string,
  ) => Effect.Effect<SecretEnvelope, StateStoreError>;
  readonly decrypt: (
    envelope: SecretEnvelope,
  ) => Effect.Effect<string, StateStoreError>;
}

type SecretsDeps = Credentials | HttpClient | Region;

const toError = (message: string) => (cause: unknown) =>
  new StateStoreError({
    message: `${message}: ${
      cause instanceof Error ? cause.message : String(cause)
    }`,
    cause: cause instanceof Error ? cause : undefined,
  });

/**
 * Build the codec for the configured secrets tier, or `undefined` for
 * `plaintext`. Construction never touches AWS — key material is
 * resolved lazily (and exactly once, via `Effect.cached`) on the first
 * encrypt/decrypt.
 */
export const makeSecretsCodec = (
  options: StateSecretsOptions,
): Effect.Effect<SecretsCodec | undefined, never, SecretsDeps> =>
  Effect.gen(function* () {
    if (options.kind === "plaintext") {
      return undefined;
    }
    const context = yield* Effect.context<SecretsDeps>();
    if (options.kind === "ssm") {
      const key = yield* Effect.cached(
        ensureSsmKey(options.parameterName ?? DEFAULT_SSM_PARAMETER).pipe(
          Effect.provideContext(context),
        ),
      );
      return {
        encrypt: (plaintext) =>
          key.pipe(Effect.flatMap((k) => aesGcmEncrypt(k, plaintext))),
        decrypt: (envelope) =>
          envelope.alg === AES_ALG
            ? key.pipe(Effect.flatMap((k) => aesGcmDecrypt(k, envelope.ct)))
            : wrongAlgorithm(envelope.alg, "ssm"),
      } satisfies SecretsCodec;
    }
    const keyId = yield* Effect.cached(
      options.keyId === undefined
        ? ensureKmsKey().pipe(Effect.provideContext(context))
        : Effect.succeed(options.keyId),
    );
    return {
      encrypt: (plaintext) =>
        keyId.pipe(
          Effect.flatMap((k) =>
            kmsEncrypt(k, plaintext).pipe(Effect.provideContext(context)),
          ),
        ),
      decrypt: (envelope) =>
        envelope.alg === KMS_ALG
          ? kmsDecrypt(envelope.ct).pipe(Effect.provideContext(context))
          : wrongAlgorithm(envelope.alg, "kms"),
    } satisfies SecretsCodec;
  });

const wrongAlgorithm = (observed: string, configured: "ssm" | "kms") =>
  Effect.fail(
    new StateStoreError({
      message:
        `State secret was encrypted with '${observed}' but this state store ` +
        `is configured with secrets: { kind: "${configured}" }. Configure ` +
        `the secrets tier that was used to write this state.`,
    }),
  );

/**
 * Walk an `encodeState`-encoded value and replace every plaintext
 * `__redacted__` marker with an encrypted `__secret__` envelope. With
 * no codec (plaintext tier) the value passes through unchanged.
 */
export const encryptStateSecrets = (
  encoded: unknown,
  codec: SecretsCodec | undefined,
): Effect.Effect<unknown, StateStoreError> => {
  if (codec === undefined) {
    return Effect.succeed(encoded);
  }
  const walk = (value: unknown): Effect.Effect<unknown, StateStoreError> => {
    if (value === null || typeof value !== "object") {
      return Effect.succeed(value);
    }
    if (Array.isArray(value)) {
      return Effect.forEach(value, walk, { concurrency: "unbounded" });
    }
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj);
    if (keys.length === 1 && keys[0] === REDACTED_MARKER) {
      return codec
        .encrypt(JSON.stringify(obj[REDACTED_MARKER]) ?? "null")
        .pipe(Effect.map((envelope) => ({ [SECRET_MARKER]: envelope })));
    }
    return Effect.forEach(
      Object.entries(obj),
      ([k, v]) => walk(v).pipe(Effect.map((r) => [k, r] as const)),
      { concurrency: "unbounded" },
    ).pipe(Effect.map((entries) => Object.fromEntries(entries)));
  };
  return walk(encoded);
};

/**
 * Walk a parsed state value and replace every `__secret__` envelope
 * with the plaintext `__redacted__` marker it encrypts, ready for
 * `reviveStateRecursive`. Legacy plaintext markers pass through
 * untouched regardless of tier, so enabling encryption upgrades
 * entries as they are rewritten — no migration step. Envelopes found
 * with no codec configured fail with a descriptive error instead of
 * surfacing ciphertext as state.
 */
export const decryptStateSecrets = (
  value: unknown,
  codec: SecretsCodec | undefined,
): Effect.Effect<unknown, StateStoreError> => {
  const walk = (value: unknown): Effect.Effect<unknown, StateStoreError> => {
    if (value === null || typeof value !== "object") {
      return Effect.succeed(value);
    }
    if (Array.isArray(value)) {
      return Effect.forEach(value, walk, { concurrency: "unbounded" });
    }
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj);
    if (keys.length === 1 && keys[0] === SECRET_MARKER) {
      const envelope = obj[SECRET_MARKER];
      if (!isSecretEnvelope(envelope)) {
        return Effect.fail(
          new StateStoreError({
            message: "Malformed encrypted secret envelope in state",
          }),
        );
      }
      if (codec === undefined) {
        return Effect.fail(
          new StateStoreError({
            message:
              "State contains encrypted secrets but this state store is " +
              'configured with secrets: { kind: "plaintext" }. Configure ' +
              "the `ssm` or `kms` secrets tier that was used to write " +
              "this state.",
          }),
        );
      }
      return codec.decrypt(envelope).pipe(
        Effect.flatMap((plaintext) =>
          Effect.try({
            try: () => JSON.parse(plaintext) as unknown,
            catch: toError("Failed to parse decrypted secret"),
          }),
        ),
        Effect.map((inner) => ({ [REDACTED_MARKER]: inner })),
      );
    }
    return Effect.forEach(
      Object.entries(obj),
      ([k, v]) => walk(v).pipe(Effect.map((r) => [k, r] as const)),
      { concurrency: "unbounded" },
    ).pipe(Effect.map((entries) => Object.fromEntries(entries)));
  };
  return walk(value);
};

// ---------------------------------------------------------------------------
// SSM-backed AES-256-GCM
// ---------------------------------------------------------------------------

/**
 * Observe-then-ensure the SecureString key parameter: read it, create
 * it with fresh random bytes if missing (tolerating the create race —
 * `Overwrite: false` guarantees the losing writer never clobbers the
 * winner's key), then read back whichever value won.
 */
const ensureSsmKey = (parameterName: string) =>
  Effect.gen(function* () {
    const existing = yield* readSsmKey(parameterName).pipe(
      Effect.catchTag("ParameterNotFound", () => Effect.succeed(undefined)),
    );
    if (existing !== undefined) {
      return existing;
    }
    const keyHex = yield* Effect.sync(() =>
      crypto.randomBytes(AES_KEY_BYTES).toString("hex"),
    );
    yield* ssm
      .putParameter({
        Name: parameterName,
        Value: keyHex,
        Type: "SecureString",
        Overwrite: false,
        Description:
          "AES-256 key encrypting secret values in the alchemy state store",
      })
      .pipe(Effect.catchTag("ParameterAlreadyExists", () => Effect.void));
    // Re-read instead of trusting our own bytes — a concurrent creator
    // may have won the race with a different key.
    return yield* readSsmKey(parameterName);
  }).pipe(
    Effect.mapError(
      toError(
        `Failed to resolve the state secrets key parameter ` +
          `'${parameterName}' (requires ssm:GetParameter and, on first ` +
          `use, ssm:PutParameter)`,
      ),
    ),
  );

const readSsmKey = (parameterName: string) =>
  ssm.getParameter({ Name: parameterName, WithDecryption: true }).pipe(
    Effect.flatMap((result) => {
      const raw = result.Parameter?.Value;
      const hex = Redacted.isRedacted(raw) ? Redacted.value(raw) : raw;
      if (
        hex === undefined ||
        !/^[0-9a-f]+$/i.test(hex) ||
        hex.length !== AES_KEY_BYTES * 2
      ) {
        return Effect.fail(
          new StateStoreError({
            message:
              `SSM parameter '${parameterName}' does not contain a ` +
              `hex-encoded ${AES_KEY_BYTES * 8}-bit key`,
          }),
        );
      }
      return Effect.succeed(Buffer.from(hex, "hex"));
    }),
  );

const aesGcmEncrypt = (key: Buffer, plaintext: string) =>
  Effect.try({
    try: (): SecretEnvelope => {
      const iv = crypto.randomBytes(AES_IV_BYTES);
      const cipher = crypto.createCipheriv(AES_ALG, key, iv);
      const body = Buffer.concat([
        cipher.update(plaintext, "utf8"),
        cipher.final(),
      ]);
      // Frame as a single base64 string: iv || ciphertext || tag.
      const ct = Buffer.concat([iv, body, cipher.getAuthTag()]).toString(
        "base64",
      );
      return { v: 1, alg: AES_ALG, ct };
    },
    catch: toError("Failed to encrypt state secret"),
  });

const aesGcmDecrypt = (key: Buffer, ct: string) =>
  Effect.try({
    try: () => {
      const framed = Buffer.from(ct, "base64");
      const iv = framed.subarray(0, AES_IV_BYTES);
      const tag = framed.subarray(framed.length - AES_TAG_BYTES);
      const body = framed.subarray(AES_IV_BYTES, framed.length - AES_TAG_BYTES);
      const decipher = crypto.createDecipheriv(AES_ALG, key, iv);
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(body), decipher.final()]).toString(
        "utf8",
      );
    },
    catch: toError(
      "Failed to decrypt state secret (was the key parameter rotated?)",
    ),
  });

// ---------------------------------------------------------------------------
// KMS
// ---------------------------------------------------------------------------

/**
 * Observe-then-ensure the auto-provisioned KMS key: resolve the
 * well-known alias, create key + alias if missing. Losing the
 * alias-create race schedules our freshly created (now orphaned) key
 * for deletion so it doesn't bill forever, then adopts the winner's.
 */
const ensureKmsKey = () =>
  Effect.gen(function* () {
    const observed = yield* kms
      .describeKey({ KeyId: DEFAULT_KMS_ALIAS })
      .pipe(
        Effect.catchTag("NotFoundException", () => Effect.succeed(undefined)),
      );
    if (observed !== undefined) {
      return DEFAULT_KMS_ALIAS;
    }
    const created = yield* kms.createKey({
      Description:
        "Encrypts secret values in the alchemy state store " +
        `(${DEFAULT_KMS_ALIAS})`,
      Tags: [{ TagKey: "alchemy:state-store", TagValue: "secrets-key" }],
    });
    const keyId = created.KeyMetadata?.KeyId;
    if (keyId === undefined) {
      return yield* Effect.fail(
        new StateStoreError({ message: "KMS CreateKey returned no KeyId" }),
      );
    }
    yield* kms
      .createAlias({ AliasName: DEFAULT_KMS_ALIAS, TargetKeyId: keyId })
      .pipe(
        Effect.catchTag("AlreadyExistsException", () =>
          // Lost the alias race — another caller provisioned the key
          // first. Retire our orphan so it doesn't cost $1/month, and
          // fall through to the winner's alias.
          kms
            .scheduleKeyDeletion({ KeyId: keyId, PendingWindowInDays: 7 })
            .pipe(Effect.asVoid, Effect.ignore),
        ),
      );
    return DEFAULT_KMS_ALIAS;
  }).pipe(
    Effect.mapError(
      toError(
        `Failed to provision the state secrets KMS key ` +
          `'${DEFAULT_KMS_ALIAS}' (requires kms:DescribeKey and, on first ` +
          `use, kms:CreateKey + kms:CreateAlias)`,
      ),
    ),
  );

const kmsEncrypt = (keyId: string, plaintext: string) =>
  Effect.gen(function* () {
    const bytes = new TextEncoder().encode(plaintext);
    if (bytes.byteLength > KMS_MAX_PLAINTEXT_BYTES) {
      return yield* Effect.fail(
        new StateStoreError({
          message:
            `State secret of ${bytes.byteLength} bytes exceeds the ` +
            `${KMS_MAX_PLAINTEXT_BYTES}-byte kms:Encrypt limit — use ` +
            `secrets: { kind: "ssm" } for large secrets`,
        }),
      );
    }
    const result = yield* kms
      .encrypt({
        KeyId: keyId,
        Plaintext: bytes,
        EncryptionContext: ENCRYPTION_CONTEXT,
      })
      .pipe(
        Effect.mapError(
          toError(
            `Failed to encrypt state secret with KMS key '${keyId}' ` +
              `(requires kms:Encrypt)`,
          ),
        ),
      );
    if (result.CiphertextBlob === undefined) {
      return yield* Effect.fail(
        new StateStoreError({
          message: "KMS Encrypt returned no CiphertextBlob",
        }),
      );
    }
    return {
      v: 1,
      alg: KMS_ALG,
      ct: Buffer.from(result.CiphertextBlob).toString("base64"),
    } satisfies SecretEnvelope;
  });

const kmsDecrypt = (ct: string) =>
  kms
    .decrypt({
      CiphertextBlob: Buffer.from(ct, "base64"),
      EncryptionContext: ENCRYPTION_CONTEXT,
    })
    .pipe(
      Effect.mapError(
        toError(
          "Failed to decrypt state secret with KMS (requires kms:Decrypt " +
            "on the state secrets key)",
        ),
      ),
      Effect.flatMap((result) => {
        const raw = result.Plaintext;
        const bytes = Redacted.isRedacted(raw) ? Redacted.value(raw) : raw;
        return bytes === undefined
          ? Effect.fail(
              new StateStoreError({
                message: "KMS Decrypt returned no Plaintext",
              }),
            )
          : Effect.succeed(Buffer.from(bytes).toString("utf8"));
      }),
    );
