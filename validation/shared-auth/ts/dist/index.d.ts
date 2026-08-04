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
export declare class UnauthorizedError extends Error {
    constructor();
}
export declare class MissingServiceCredentialError extends Error {
    constructor();
}
export declare class SharedAuthHttpError extends Error {
    readonly path: string;
    readonly status: number;
    constructor(path: string, status: number);
}
export declare class SharedAuthTransportError extends Error {
    readonly path: string;
    constructor(path: string);
}
export declare class SharedAuthTimeoutError extends Error {
    readonly path: string;
    readonly timeoutMs: number;
    constructor(path: string, timeoutMs: number);
}
export declare class SharedAuthRequestTooLargeError extends Error {
    readonly path: string;
    readonly maxRequestBytes: number;
    constructor(path: string, maxRequestBytes: number);
}
export declare class SharedAuthResponseTooLargeError extends Error {
    readonly path: string;
    readonly maxResponseBytes: number;
    constructor(path: string, maxResponseBytes: number);
}
export declare class SharedAuthDecodeError extends Error {
    readonly path: string;
    constructor(path: string);
}
export declare function hasAssurance(introspection: Introspection, requiredAcr: string): boolean;
export declare function usedMethod(introspection: Introspection, method: string): boolean;
export declare function hasRole(introspection: Introspection, role: string): boolean;
export declare class SharedAuthClient {
    private readonly base;
    private readonly doFetch;
    private readonly timeoutMs;
    private readonly maxRequestBytes;
    private readonly maxResponseBytes;
    private serviceCredential?;
    constructor(base: string, fetchImpl?: typeof fetch, serviceCredential?: string);
    constructor(base: string, options?: SharedAuthClientOptions);
    /** Configure the service-to-service bearer required by protected introspection. */
    withServiceCredential(credential: string): this;
    withoutServiceCredential(): this;
    /** Supabase access token → shared-auth token. Throws UnauthorizedError on 401. */
    exchange(supabaseToken: string): Promise<ExchangeResponse>;
    /** Missing service credentials fail locally before fetch is called. */
    introspect(token: string): Promise<Introspection>;
    /** Lightweight bearer check: true (200) / false (401). */
    verify(token: string): Promise<boolean>;
    /** The server's public JWKS. */
    jwks(): Promise<{
        keys: unknown[];
    }>;
    capabilities(): Promise<Capabilities>;
    factors(accessToken: string): Promise<Factor[]>;
    enrollTotp(accessToken: string, label?: string): Promise<TotpEnrollment>;
    confirmTotp(accessToken: string, factorId: string, code: string): Promise<StepUpResponse>;
    deleteFactor(accessToken: string, factorId: string): Promise<void>;
    createChallenge(accessToken: string, kind: ChallengeKind): Promise<ChallengeStart>;
    verifyChallenge(accessToken: string, challengeId: string, code: string): Promise<StepUpResponse>;
    startPasskeyRegistration(accessToken: string, label?: string): Promise<CeremonyStart>;
    finishPasskeyRegistration(accessToken: string, challengeId: string, credential: unknown, label?: string): Promise<Factor>;
    startPasskeyAuthentication(accessToken: string): Promise<CeremonyStart>;
    finishPasskeyAuthentication(accessToken: string, challengeId: string, credential: unknown): Promise<StepUpResponse>;
    private authedJson;
    private requestJson;
    private fetchResponse;
    private assertRequestBodySize;
    private withDeadline;
    private readJson;
}
