// Thin typed client for the shared-auth server HTTP API (see ../../ENDPOINTS.md).
// Fetch-based: Node 18+, Workers, Deno, Bun, browsers.

export interface ExchangeResponse {
  access_token: string;
  token_type: string;
  expires_at: number;
  shared_user_id: string;
  project?: string | null;
  provider?: string | null;
  provider_tenant?: string | null;
}

export interface StepUpResponse {
  access_token: string;
  token_type: string;
  expires_at: number;
  amr: string[];
  acr?: string | null;
}

export interface Introspection {
  active: boolean;
  sub?: string;
  sid?: string;
  project?: string;
  provider?: string;
  provider_tenant?: string;
  provider_subject?: string;
  email?: string;
  email_verified?: boolean;
  roles?: string[];
  amr?: string[];
  acr?: string;
  exp?: number;
  [k: string]: unknown;
}

export interface Capabilities {
  mfa_enabled: boolean;
  methods: string[];
  threefa_import_scheme?: string | null;
  biometric_model?: string | null;
}

export interface Factor {
  factor_id: string;
  kind: string;
  label?: string | null;
  enabled: boolean;
  confirmed_at?: string | null;
  last_used_at?: string | null;
  created_at: string;
}

export interface TotpEnrollment {
  factor_id: string;
  secret_base32: string;
  otpauth_uri: string;
  threefa_import_uri: string;
}

export type ChallengeKind = "email_otp" | "sms_otp";

export interface ChallengeStart {
  challenge_id: string;
  expires_at: string;
  delivery: string;
}

export interface CeremonyStart {
  challenge_id: string;
  options: unknown;
  expires_at: string;
}

export interface SharedAuthClientOptions {
  fetch?: typeof fetch;
  serviceCredential?: string;
  /** End-to-end request deadline, including response-body parsing. */
  timeoutMs?: number;
  /** Maximum encoded request-body size in bytes. */
  maxRequestBytes?: number;
  /** Maximum decoded JSON response size in bytes. */
  maxResponseBytes?: number;
}

export class UnauthorizedError extends Error {
  constructor() {
    super("unauthorized");
    this.name = "UnauthorizedError";
  }
}

export class MissingServiceCredentialError extends Error {
  constructor() {
    super("introspection service credential is required");
    this.name = "MissingServiceCredentialError";
  }
}

export class SharedAuthHttpError extends Error {
  readonly path: string;
  readonly status: number;

  constructor(path: string, status: number) {
    super(`shared-auth ${path}: ${status}`);
    this.name = "SharedAuthHttpError";
    this.path = path;
    this.status = status;
  }
}

export class SharedAuthTransportError extends Error {
  readonly path: string;

  constructor(path: string) {
    super(`shared-auth transport failed at ${path}`);
    this.name = "SharedAuthTransportError";
    this.path = path;
  }
}

export class SharedAuthTimeoutError extends Error {
  readonly path: string;
  readonly timeoutMs: number;

  constructor(path: string, timeoutMs: number) {
    super(`shared-auth request timed out at ${path}`);
    this.name = "SharedAuthTimeoutError";
    this.path = path;
    this.timeoutMs = timeoutMs;
  }
}

export class SharedAuthRequestTooLargeError extends Error {
  readonly path: string;
  readonly maxRequestBytes: number;

  constructor(path: string, maxRequestBytes: number) {
    super(`shared-auth request exceeded ${maxRequestBytes} bytes at ${path}`);
    this.name = "SharedAuthRequestTooLargeError";
    this.path = path;
    this.maxRequestBytes = maxRequestBytes;
  }
}

export class SharedAuthResponseTooLargeError extends Error {
  readonly path: string;
  readonly maxResponseBytes: number;

  constructor(path: string, maxResponseBytes: number) {
    super(`shared-auth response exceeded ${maxResponseBytes} bytes at ${path}`);
    this.name = "SharedAuthResponseTooLargeError";
    this.path = path;
    this.maxResponseBytes = maxResponseBytes;
  }
}

export class SharedAuthDecodeError extends Error {
  readonly path: string;

  constructor(path: string) {
    super(`shared-auth returned invalid JSON at ${path}`);
    this.name = "SharedAuthDecodeError";
    this.path = path;
  }
}

export function hasAssurance(
  introspection: Introspection,
  requiredAcr: string,
): boolean {
  return introspection.active && introspection.acr === requiredAcr;
}

export function usedMethod(
  introspection: Introspection,
  method: string,
): boolean {
  return introspection.active && (introspection.amr?.includes(method) ?? false);
}

export function hasRole(introspection: Introspection, role: string): boolean {
  return introspection.active && (introspection.roles?.includes(role) ?? false);
}

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_REQUEST_BYTES = 256 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_CREDENTIAL_BYTES = 16 * 1024;

export class SharedAuthClient {
  private readonly base: string;
  private readonly doFetch: typeof fetch;
  private readonly timeoutMs: number;
  private readonly maxRequestBytes: number;
  private readonly maxResponseBytes: number;
  private serviceCredential?: string;

  constructor(
    base: string,
    fetchImpl?: typeof fetch,
    serviceCredential?: string,
  );
  constructor(base: string, options?: SharedAuthClientOptions);
  constructor(
    base: string,
    fetchOrOptions?: typeof fetch | SharedAuthClientOptions,
    serviceCredential?: string,
  ) {
    const options =
      typeof fetchOrOptions === "function"
        ? { fetch: fetchOrOptions, serviceCredential }
        : (fetchOrOptions ?? {});

    this.base = normalizeBase(base);
    const fetchImpl = options.fetch ?? globalThis.fetch;
    if (typeof fetchImpl !== "function") {
      throw new TypeError("a fetch implementation is required");
    }
    // Native browser fetch validates its receiver. Calling a stored function as
    // `this.doFetch(...)` would bind the SharedAuthClient instance and fail
    // before a request is sent. The wrapper fixes the receiver at globalThis
    // while preserving injected fetch implementations.
    this.doFetch = (input, init) => fetchImpl.call(globalThis, input, init);
    this.timeoutMs = positiveInteger(
      options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      "timeoutMs",
    );
    this.maxRequestBytes = positiveInteger(
      options.maxRequestBytes ?? DEFAULT_MAX_REQUEST_BYTES,
      "maxRequestBytes",
    );
    this.maxResponseBytes = positiveInteger(
      options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
      "maxResponseBytes",    );
    this.serviceCredential = normalizeOptionalCredential(
      options.serviceCredential,
      "serviceCredential",
    );
  }

  /** Configure the service-to-service bearer required by protected introspection. */
  withServiceCredential(credential: string): this {
    this.serviceCredential = requiredCredential(
      credential,
      "serviceCredential",
    );
    return this;
  }

  withoutServiceCredential(): this {
    this.serviceCredential = undefined;
    return this;
  }

  /** Supabase access token → shared-auth token. Throws UnauthorizedError on 401. */
  async exchange(supabaseToken: string): Promise<ExchangeResponse> {
    return this.requestJson<ExchangeResponse>("/auth/exchange", {
      method: "POST",
      headers: {
        authorization: bearer(supabaseToken, "supabaseToken"),
      },
    });
  }

  /** Missing service credentials fail locally before fetch is called. */
  async introspect(token: string): Promise<Introspection> {
    const serviceCredential = this.serviceCredential;
    if (serviceCredential === undefined) {
      throw new MissingServiceCredentialError();
    }
    return this.requestJson<Introspection>("/auth/introspect", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${serviceCredential}`,
      },
      body: encodeJson({ token: requiredCredential(token, "token") }),
    });
  }

  /** Lightweight bearer check: true (200) / false (401). */
  async verify(token: string): Promise<boolean> {
    const path = "/auth/verify";
    return this.withDeadline(path, async (signal) => {
      const resp = await this.fetchResponse(path, {
        headers: { authorization: bearer(token, "token") },
        signal,
      });
      if (resp.status === 200) return true;
      if (resp.status === 401) return false;
      throw new SharedAuthHttpError(path, resp.status);
    });
  }

  /** The server's public JWKS. */
  jwks(): Promise<{ keys: unknown[] }> {
    return this.requestJson<{ keys: unknown[] }>("/.well-known/jwks.json");
  }

  capabilities(): Promise<Capabilities> {
    return this.requestJson<Capabilities>("/auth/capabilities");
  }

  factors(accessToken: string): Promise<Factor[]> {
    return this.authedJson<Factor[]>("/auth/factors", accessToken);
  }

  enrollTotp(
    accessToken: string,
    label?: string,
  ): Promise<TotpEnrollment> {
    return this.authedJson<TotpEnrollment>(
      "/auth/factors/totp/enroll",
      accessToken,
      "POST",
      { label },
    );
  }

  confirmTotp(
    accessToken: string,
    factorId: string,
    code: string,
  ): Promise<StepUpResponse> {
    return this.authedJson<StepUpResponse>(
      "/auth/factors/totp/confirm",
      accessToken,
      "POST",
      {
        factor_id: requiredField(factorId, "factorId"),
        code: requiredField(code, "code"),
      },
    );
  }

  async deleteFactor(accessToken: string, factorId: string): Promise<void> {
    const encodedFactorId = encodeURIComponent(
      requiredField(factorId, "factorId"),
    );
    await this.requestJson<unknown>(
      `/auth/factors/${encodedFactorId}`,
      {
        method: "DELETE",
        headers: { authorization: bearer(accessToken, "accessToken") },
      },
      true,
    );
  }

  createChallenge(
    accessToken: string,
    kind: ChallengeKind,
  ): Promise<ChallengeStart> {
    if (kind !== "email_otp" && kind !== "sms_otp") {
      throw new TypeError("kind must be email_otp or sms_otp");
    }
    return this.authedJson<ChallengeStart>(
      "/auth/challenges",
      accessToken,
      "POST",
      { kind },
    );
  }

  verifyChallenge(
    accessToken: string,
    challengeId: string,
    code: string,
  ): Promise<StepUpResponse> {
    const encodedChallengeId = encodeURIComponent(
      requiredField(challengeId, "challengeId"),
    );
    return this.authedJson<StepUpResponse>(
      `/auth/challenges/${encodedChallengeId}/verify`,
      accessToken,
      "POST",
      { code: requiredField(code, "code") },
    );
  }

  startPasskeyRegistration(
    accessToken: string,
    label?: string,
  ): Promise<CeremonyStart> {
    return this.authedJson<CeremonyStart>(
      "/auth/passkeys/registration/options",
      accessToken,
      "POST",
      { label },
    );
  }

  finishPasskeyRegistration(
    accessToken: string,
    challengeId: string,
    credential: unknown,
    label?: string,
  ): Promise<Factor> {
    return this.authedJson<Factor>(
      "/auth/passkeys/registration/verify",
      accessToken,
      "POST",
      {
        challenge_id: requiredField(challengeId, "challengeId"),
        credential,
        label,
      },
    );
  }

  startPasskeyAuthentication(accessToken: string): Promise<CeremonyStart> {
    return this.authedJson<CeremonyStart>(
      "/auth/passkeys/authentication/options",
      accessToken,
      "POST",
      {},
    );
  }

  finishPasskeyAuthentication(
    accessToken: string,
    challengeId: string,
    credential: unknown,
  ): Promise<StepUpResponse> {
    return this.authedJson<StepUpResponse>(
      "/auth/passkeys/authentication/verify",
      accessToken,
      "POST",
      {
        challenge_id: requiredField(challengeId, "challengeId"),
        credential,
      },
    );
  }

  private authedJson<T>(
    path: string,
    accessToken: string,
    method: "GET" | "POST" = "GET",
    body?: unknown,
  ): Promise<T> {
    const headers: Record<string, string> = {
      authorization: bearer(accessToken, "accessToken"),
    };
    if (body !== undefined) headers["content-type"] = "application/json";
    return this.requestJson<T>(path, {
      method,
      headers,
      body: body === undefined ? undefined : encodeJson(body),
    });
  }

  private async requestJson<T>(
    path: string,
    init: RequestInit = {},
    allowEmpty = false,
  ): Promise<T> {
    return this.withDeadline(path, async (signal) => {
      const resp = await this.fetchResponse(path, { ...init, signal });
      if (resp.status === 401) throw new UnauthorizedError();
      if (!resp.ok) throw new SharedAuthHttpError(path, resp.status);
      if (allowEmpty || resp.status === 204) return undefined as T;
      return this.readJson<T>(path, resp);
    });
  }

  private async fetchResponse(
    path: string,
    init: RequestInit,
  ): Promise<Response> {
    this.assertRequestBodySize(path, init.body);
    const headers = new Headers(init.headers);
    if (!headers.has("accept")) headers.set("accept", "application/json");

    try {
      return await this.doFetch(`${this.base}${path}`, {
        ...init,
        headers,
        credentials: "omit",
        redirect: "error",
        referrerPolicy: "no-referrer",
      });
    } catch (error) {
      if (init.signal?.aborted) throw error;
      throw new SharedAuthTransportError(path);
    }
  }

  private assertRequestBodySize(
    path: string,
    body: BodyInit | null | undefined,
  ): void {
    if (typeof body !== "string") return;
    if (utf8Length(body) > this.maxRequestBytes) {
      throw new SharedAuthRequestTooLargeError(path, this.maxRequestBytes);
    }
  }

  private async withDeadline<T>(
    path: string,
    operation: (signal: AbortSignal) => Promise<T>,
  ): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);    try {
      return await operation(controller.signal);
    } catch (error) {
      if (controller.signal.aborted) {
        throw new SharedAuthTimeoutError(path, this.timeoutMs);
      }
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  private async readJson<T>(path: string, response: Response): Promise<T> {
    const declaredLength = response.headers.get("content-length");
    if (declaredLength !== null) {
      const parsedLength = Number(declaredLength);
      if (
        Number.isFinite(parsedLength) &&
        parsedLength > this.maxResponseBytes
      ) {
        throw new SharedAuthResponseTooLargeError(
          path,
          this.maxResponseBytes,
        );
      }
    }

    const body = response.body;
    if (body === null) throw new SharedAuthDecodeError(path);

    const reader = body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > this.maxResponseBytes) {
          await reader.cancel();
          throw new SharedAuthResponseTooLargeError(
            path,
            this.maxResponseBytes,
          );
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }

    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }

    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      throw new SharedAuthDecodeError(path);
    }

    try {
      return JSON.parse(text) as T;
    } catch {
      throw new SharedAuthDecodeError(path);
    }
  }
}

function normalizeBase(input: string): string {
  const trimmed = input.trim();
  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    throw new TypeError("shared-auth base URL must be absolute HTTP(S)");
  }

  if (
    (url.protocol !== "https:" && url.protocol !== "http:") ||
    url.hostname.length === 0 ||
    url.username.length > 0 ||
    url.password.length > 0 ||
    url.search.length > 0 ||
    url.hash.length > 0
  ) {
    throw new TypeError(
      "shared-auth base URL must be credential-free HTTP(S) without query or fragment",
    );
  }

  if (url.protocol === "http:" && !isLoopbackHostname(url.hostname)) {
    throw new TypeError(
      "shared-auth base URL must use HTTPS except for loopback development URLs",
    );
  }

  const pathname = url.pathname.replace(/\/+$/, "");
  return `${url.origin}${pathname}`;
}

function isLoopbackHostname(hostname: string): boolean {
  const normalized = hostname
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .replace(/\.$/, "");
  if (normalized === "localhost" || normalized === "::1") return true;

  const octets = normalized.split(".");
  if (octets.length !== 4 || octets[0] !== "127") return false;
  return octets.every((octet) => {
    if (!/^\d{1,3}$/.test(octet)) return false;
    const value = Number(octet);
    return value >= 0 && value <= 255;
  });
}

function positiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${name} must be a positive safe integer`);
  }
  return value;
}

function normalizeOptionalCredential(
  value: string | undefined,
  name: string,
): string | undefined {
  return value === undefined ? undefined : requiredCredential(value, name);
}

function requiredCredential(value: string, name: string): string {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value) {
    throw new TypeError(
      `${name} must be a non-empty credential without surrounding whitespace`,
    );
  }
  if (containsControlCharacters(value)) {
    throw new TypeError(`${name} must not contain control characters`);
  }
  if (utf8Length(value) > MAX_CREDENTIAL_BYTES) {
    throw new TypeError(`${name} exceeds the credential size limit`);
  }
  return value;
}

function requiredField(value: string, name: string): string {
  if (typeof value !== "string") {
    throw new TypeError(`${name} must be a non-empty string`);
  }
  const normalized = value.trim();
  if (normalized.length === 0) {
    throw new TypeError(`${name} must be a non-empty string`);
  }
  if (containsControlCharacters(normalized)) {
    throw new TypeError(`${name} must not contain control characters`);
  }
  return normalized;
}

function bearer(value: string, name: string): string {
  return `Bearer ${requiredCredential(value, name)}`;
}

function encodeJson(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    throw new TypeError("shared-auth request body is not JSON-serializable");
  }
}

function containsControlCharacters(value: string): boolean {
  return /[\u0000-\u001f\u007f]/.test(value);
}

function utf8Length(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}
