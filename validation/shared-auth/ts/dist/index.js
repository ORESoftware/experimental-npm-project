// Thin typed client for the shared-auth server HTTP API (see ../../ENDPOINTS.md).
// Fetch-based: Node 18+, Workers, Deno, Bun, browsers.
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
    path;
    status;
    constructor(path, status) {
        super(`shared-auth ${path}: ${status}`);
        this.name = "SharedAuthHttpError";
        this.path = path;
        this.status = status;
    }
}
export class SharedAuthTransportError extends Error {
    path;
    constructor(path) {
        super(`shared-auth transport failed at ${path}`);
        this.name = "SharedAuthTransportError";
        this.path = path;
    }
}
export class SharedAuthTimeoutError extends Error {
    path;
    timeoutMs;
    constructor(path, timeoutMs) {
        super(`shared-auth request timed out at ${path}`);
        this.name = "SharedAuthTimeoutError";
        this.path = path;
        this.timeoutMs = timeoutMs;
    }
}
export class SharedAuthRequestTooLargeError extends Error {
    path;
    maxRequestBytes;
    constructor(path, maxRequestBytes) {
        super(`shared-auth request exceeded ${maxRequestBytes} bytes at ${path}`);
        this.name = "SharedAuthRequestTooLargeError";
        this.path = path;
        this.maxRequestBytes = maxRequestBytes;
    }
}
export class SharedAuthResponseTooLargeError extends Error {
    path;
    maxResponseBytes;
    constructor(path, maxResponseBytes) {
        super(`shared-auth response exceeded ${maxResponseBytes} bytes at ${path}`);
        this.name = "SharedAuthResponseTooLargeError";
        this.path = path;
        this.maxResponseBytes = maxResponseBytes;
    }
}
export class SharedAuthDecodeError extends Error {
    path;
    constructor(path) {
        super(`shared-auth returned invalid JSON at ${path}`);
        this.name = "SharedAuthDecodeError";
        this.path = path;
    }
}
export function hasAssurance(introspection, requiredAcr) {
    return introspection.active && introspection.acr === requiredAcr;
}
export function usedMethod(introspection, method) {
    return introspection.active && (introspection.amr?.includes(method) ?? false);
}
export function hasRole(introspection, role) {
    return introspection.active && (introspection.roles?.includes(role) ?? false);
}
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_REQUEST_BYTES = 256 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_CREDENTIAL_BYTES = 16 * 1024;
export class SharedAuthClient {
    base;
    doFetch;
    timeoutMs;
    maxRequestBytes;
    maxResponseBytes;
    serviceCredential;
    constructor(base, fetchOrOptions, serviceCredential) {
        const options = typeof fetchOrOptions === "function"
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
        this.timeoutMs = positiveInteger(options.timeoutMs ?? DEFAULT_TIMEOUT_MS, "timeoutMs");
        this.maxRequestBytes = positiveInteger(options.maxRequestBytes ?? DEFAULT_MAX_REQUEST_BYTES, "maxRequestBytes");
        this.maxResponseBytes = positiveInteger(options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES, "maxResponseBytes");
        this.serviceCredential = normalizeOptionalCredential(options.serviceCredential, "serviceCredential");
    }
    /** Configure the service-to-service bearer required by protected introspection. */
    withServiceCredential(credential) {
        this.serviceCredential = requiredCredential(credential, "serviceCredential");
        return this;
    }
    withoutServiceCredential() {
        this.serviceCredential = undefined;
        return this;
    }
    /** Supabase access token → shared-auth token. Throws UnauthorizedError on 401. */
    async exchange(supabaseToken) {
        return this.requestJson("/auth/exchange", {
            method: "POST",
            headers: {
                authorization: bearer(supabaseToken, "supabaseToken"),
            },
        });
    }
    /** Missing service credentials fail locally before fetch is called. */
    async introspect(token) {
        const serviceCredential = this.serviceCredential;
        if (serviceCredential === undefined) {
            throw new MissingServiceCredentialError();
        }
        return this.requestJson("/auth/introspect", {
            method: "POST",
            headers: {
                "content-type": "application/json",
                authorization: `Bearer ${serviceCredential}`,
            },
            body: encodeJson({ token: requiredCredential(token, "token") }),
        });
    }
    /** Lightweight bearer check: true (200) / false (401). */
    async verify(token) {
        const path = "/auth/verify";
        return this.withDeadline(path, async (signal) => {
            const resp = await this.fetchResponse(path, {
                headers: { authorization: bearer(token, "token") },
                signal,
            });
            if (resp.status === 200)
                return true;
            if (resp.status === 401)
                return false;
            throw new SharedAuthHttpError(path, resp.status);
        });
    }
    /** The server's public JWKS. */
    jwks() {
        return this.requestJson("/.well-known/jwks.json");
    }
    capabilities() {
        return this.requestJson("/auth/capabilities");
    }
    factors(accessToken) {
        return this.authedJson("/auth/factors", accessToken);
    }
    enrollTotp(accessToken, label) {
        return this.authedJson("/auth/factors/totp/enroll", accessToken, "POST", { label });
    }
    confirmTotp(accessToken, factorId, code) {
        return this.authedJson("/auth/factors/totp/confirm", accessToken, "POST", {
            factor_id: requiredField(factorId, "factorId"),
            code: requiredField(code, "code"),
        });
    }
    async deleteFactor(accessToken, factorId) {
        const encodedFactorId = encodeURIComponent(requiredField(factorId, "factorId"));
        await this.requestJson(`/auth/factors/${encodedFactorId}`, {
            method: "DELETE",
            headers: { authorization: bearer(accessToken, "accessToken") },
        }, true);
    }
    createChallenge(accessToken, kind) {
        if (kind !== "email_otp" && kind !== "sms_otp") {
            throw new TypeError("kind must be email_otp or sms_otp");
        }
        return this.authedJson("/auth/challenges", accessToken, "POST", { kind });
    }
    verifyChallenge(accessToken, challengeId, code) {
        const encodedChallengeId = encodeURIComponent(requiredField(challengeId, "challengeId"));
        return this.authedJson(`/auth/challenges/${encodedChallengeId}/verify`, accessToken, "POST", { code: requiredField(code, "code") });
    }
    startPasskeyRegistration(accessToken, label) {
        return this.authedJson("/auth/passkeys/registration/options", accessToken, "POST", { label });
    }
    finishPasskeyRegistration(accessToken, challengeId, credential, label) {
        return this.authedJson("/auth/passkeys/registration/verify", accessToken, "POST", {
            challenge_id: requiredField(challengeId, "challengeId"),
            credential,
            label,
        });
    }
    startPasskeyAuthentication(accessToken) {
        return this.authedJson("/auth/passkeys/authentication/options", accessToken, "POST", {});
    }
    finishPasskeyAuthentication(accessToken, challengeId, credential) {
        return this.authedJson("/auth/passkeys/authentication/verify", accessToken, "POST", {
            challenge_id: requiredField(challengeId, "challengeId"),
            credential,
        });
    }
    authedJson(path, accessToken, method = "GET", body) {
        const headers = {
            authorization: bearer(accessToken, "accessToken"),
        };
        if (body !== undefined)
            headers["content-type"] = "application/json";
        return this.requestJson(path, {
            method,
            headers,
            body: body === undefined ? undefined : encodeJson(body),
        });
    }
    async requestJson(path, init = {}, allowEmpty = false) {
        return this.withDeadline(path, async (signal) => {
            const resp = await this.fetchResponse(path, { ...init, signal });
            if (resp.status === 401)
                throw new UnauthorizedError();
            if (!resp.ok)
                throw new SharedAuthHttpError(path, resp.status);
            if (allowEmpty || resp.status === 204)
                return undefined;
            return this.readJson(path, resp);
        });
    }
    async fetchResponse(path, init) {
        this.assertRequestBodySize(path, init.body);
        const headers = new Headers(init.headers);
        if (!headers.has("accept"))
            headers.set("accept", "application/json");
        try {
            return await this.doFetch(`${this.base}${path}`, {
                ...init,
                headers,
                credentials: "omit",
                redirect: "error",
                referrerPolicy: "no-referrer",
            });
        }
        catch (error) {
            if (init.signal?.aborted)
                throw error;
            throw new SharedAuthTransportError(path);
        }
    }
    assertRequestBodySize(path, body) {
        if (typeof body !== "string")
            return;
        if (utf8Length(body) > this.maxRequestBytes) {
            throw new SharedAuthRequestTooLargeError(path, this.maxRequestBytes);
        }
    }
    async withDeadline(path, operation) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this.timeoutMs);
        try {
            return await operation(controller.signal);
        }
        catch (error) {
            if (controller.signal.aborted) {
                throw new SharedAuthTimeoutError(path, this.timeoutMs);
            }
            throw error;
        }
        finally {
            clearTimeout(timer);
        }
    }
    async readJson(path, response) {
        const declaredLength = response.headers.get("content-length");
        if (declaredLength !== null) {
            const parsedLength = Number(declaredLength);
            if (Number.isFinite(parsedLength) &&
                parsedLength > this.maxResponseBytes) {
                throw new SharedAuthResponseTooLargeError(path, this.maxResponseBytes);
            }
        }
        const body = response.body;
        if (body === null)
            throw new SharedAuthDecodeError(path);
        const reader = body.getReader();
        const chunks = [];
        let total = 0;
        try {
            while (true) {
                const { done, value } = await reader.read();
                if (done)
                    break;
                total += value.byteLength;
                if (total > this.maxResponseBytes) {
                    await reader.cancel();
                    throw new SharedAuthResponseTooLargeError(path, this.maxResponseBytes);
                }
                chunks.push(value);
            }
        }
        finally {
            reader.releaseLock();
        }
        const bytes = new Uint8Array(total);
        let offset = 0;
        for (const chunk of chunks) {
            bytes.set(chunk, offset);
            offset += chunk.byteLength;
        }
        let text;
        try {
            text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        }
        catch {
            throw new SharedAuthDecodeError(path);
        }
        try {
            return JSON.parse(text);
        }
        catch {
            throw new SharedAuthDecodeError(path);
        }
    }
}
function normalizeBase(input) {
    const trimmed = input.trim();
    let url;
    try {
        url = new URL(trimmed);
    }
    catch {
        throw new TypeError("shared-auth base URL must be absolute HTTP(S)");
    }
    if ((url.protocol !== "https:" && url.protocol !== "http:") ||
        url.hostname.length === 0 ||
        url.username.length > 0 ||
        url.password.length > 0 ||
        url.search.length > 0 ||
        url.hash.length > 0) {
        throw new TypeError("shared-auth base URL must be credential-free HTTP(S) without query or fragment");
    }
    if (url.protocol === "http:" && !isLoopbackHostname(url.hostname)) {
        throw new TypeError("shared-auth base URL must use HTTPS except for loopback development URLs");
    }
    const pathname = url.pathname.replace(/\/+$/, "");
    return `${url.origin}${pathname}`;
}
function isLoopbackHostname(hostname) {
    const normalized = hostname
        .toLowerCase()
        .replace(/^\[|\]$/g, "")
        .replace(/\.$/, "");
    if (normalized === "localhost" || normalized === "::1")
        return true;
    const octets = normalized.split(".");
    if (octets.length !== 4 || octets[0] !== "127")
        return false;
    return octets.every((octet) => {
        if (!/^\d{1,3}$/.test(octet))
            return false;
        const value = Number(octet);
        return value >= 0 && value <= 255;
    });
}
function positiveInteger(value, name) {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new TypeError(`${name} must be a positive safe integer`);
    }
    return value;
}
function normalizeOptionalCredential(value, name) {
    return value === undefined ? undefined : requiredCredential(value, name);
}
function requiredCredential(value, name) {
    if (typeof value !== "string" || value.length === 0 || value.trim() !== value) {
        throw new TypeError(`${name} must be a non-empty credential without surrounding whitespace`);
    }
    if (containsControlCharacters(value)) {
        throw new TypeError(`${name} must not contain control characters`);
    }
    if (utf8Length(value) > MAX_CREDENTIAL_BYTES) {
        throw new TypeError(`${name} exceeds the credential size limit`);
    }
    return value;
}
function requiredField(value, name) {
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
function bearer(value, name) {
    return `Bearer ${requiredCredential(value, name)}`;
}
function encodeJson(value) {
    try {
        return JSON.stringify(value);
    }
    catch {
        throw new TypeError("shared-auth request body is not JSON-serializable");
    }
}
function containsControlCharacters(value) {
    return /[\u0000-\u001f\u007f]/.test(value);
}
function utf8Length(value) {
    return new TextEncoder().encode(value).byteLength;
}
