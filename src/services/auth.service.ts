import apiService from './api';
import type {
  PasskeyChallengeRequest,
  PasskeyChallengeResponse,
  PasskeyCredentialRequest,
  PasskeySessionResult,
  User,
} from '@/types';

const PASSKEY_ENDPOINTS = {
  registerOptions: '/auth/passkey/register/options',
  registerVerify: '/auth/passkey/register/verify',
  loginOptions: '/auth/passkey/login/options',
  loginVerify: '/auth/passkey/login/verify',
} as const;

interface BrowserCredentialResponse {
  clientDataJSON: ArrayBuffer;
  attestationObject?: ArrayBuffer;
  authenticatorData?: ArrayBuffer;
  signature?: ArrayBuffer;
  userHandle?: ArrayBuffer | null;
  getTransports?: () => string[];
}

function isBrowser(): boolean {
  return typeof window !== 'undefined' && typeof navigator !== 'undefined';
}

function isSecureContext(): boolean {
  if (!isBrowser()) return false;
  return window.isSecureContext
    || window.location.hostname === 'localhost'
    || window.location.hostname === '127.0.0.1';
}

function toBase64Url(value: ArrayBuffer): string {
  const bytes = new Uint8Array(value);
  let binary = '';
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });

  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function base64UrlToArrayBuffer(value: string): ArrayBuffer {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes.buffer;
}

function toCredentialPayload(credential: PublicKeyCredential): PasskeyCredentialRequest {
  const response = credential.response as BrowserCredentialResponse;
  const payload: PasskeyCredentialRequest = {
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults?.() ?? {},
    response: {
      clientDataJSON: toBase64Url(response.clientDataJSON),
    },
  };

  if (typeof response.attestationObject !== 'undefined') {
    payload.response.attestationObject = toBase64Url(response.attestationObject);
  }

  if (typeof response.authenticatorData !== 'undefined') {
    payload.response.authenticatorData = toBase64Url(response.authenticatorData);
  }

  if (typeof response.signature !== 'undefined') {
    payload.response.signature = toBase64Url(response.signature);
  }

  if (response.userHandle) {
    payload.response.userHandle = toBase64Url(response.userHandle);
  }

  if (typeof response.getTransports === 'function') {
    payload.response.transports = response.getTransports();
  }

  return payload;
}

/**
 * Service for handling authentication-related tasks beyond basic API calls,
 * such as state persistence in local browser storage and session destruction.
 */
class AuthService {
  private resolvePasskeyBaseUrl(): string {
    if (typeof window !== 'undefined') {
      const configuredBase = process.env.NEXT_PUBLIC_API_BASE_URL;
      return configuredBase || window.location.origin;
    }

    return process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:2333';
  }

  private async postPasskeyChallenge<T>(endpoint: string, payload: Record<string, unknown>): Promise<T> {
    const baseUrl = this.resolvePasskeyBaseUrl().replace(/\/+$/, '');
    const response = await fetch(`${baseUrl}${endpoint}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
      credentials: 'include',
    });

    if (!response.ok) {
      let message = `Passkey request failed (${response.status})`;
      try {
        const errorBody = await response.json();
        message = errorBody?.message || errorBody?.error || message;
      } catch {
        // Ignore invalid JSON and fall back to the default message.
      }
      throw new Error(message);
    }

    return (await response.json()) as T;
  }

  private persistSession(token: string, user?: User): void {
    if (typeof window === 'undefined') return;
    apiService.setToken(token);
    localStorage.setItem('auth_token', token);
    if (user) {
      localStorage.setItem('user_data', JSON.stringify(user));
    }
  }

  private clearSession(): void {
    if (typeof window === 'undefined') return;
    localStorage.removeItem('auth_token');
    localStorage.removeItem('user_data');
    localStorage.removeItem('refresh_token');
    sessionStorage.clear();
  }

  isPasskeyBrowserSupported(): boolean {
    return isBrowser() && 'PublicKeyCredential' in window && 'credentials' in navigator;
  }

  async beginPasskeyRegistration(data: PasskeyChallengeRequest = {}): Promise<PasskeyChallengeResponse['data']> {
    if (!this.isPasskeyBrowserSupported()) {
      throw new Error('Passkeys require a browser with WebAuthn support. Use email/password or Google sign-in as a fallback.');
    }

    if (!isSecureContext()) {
      throw new Error('Passkeys require HTTPS or localhost support. Use email/password or Google sign-in until the app is served securely.');
    }

    const response = await this.postPasskeyChallenge<PasskeyChallengeResponse>(
      PASSKEY_ENDPOINTS.registerOptions,
      data,
    );

    if (!response.success || !response.data?.challenge) {
      throw new Error(response.message || 'The backend did not return a valid passkey registration challenge.');
    }

    return response.data;
  }

  async registerWithPasskey(data: PasskeyChallengeRequest = {}): Promise<PasskeySessionResult['data']> {
    const challenge = await this.beginPasskeyRegistration(data);
    if (!challenge.user || !challenge.rpName || !challenge.pubKeyCredParams) {
      throw new Error('The backend registration challenge is missing required WebAuthn user, RP, or credential parameters.');
    }

    const { challenge: challengeValue, rpId, rpName, user, ...options } = challenge;
    const credential = await navigator.credentials.create({
      publicKey: {
        ...options,
        challenge: base64UrlToArrayBuffer(challengeValue),
        rp: { id: rpId, name: rpName },
        user: { ...user, id: base64UrlToArrayBuffer(user.id) },
        excludeCredentials: challenge.excludeCredentials?.map((item) => ({
          ...item,
          id: base64UrlToArrayBuffer(item.id),
        })),
      } as PublicKeyCredentialCreationOptions,
    });

    if (!credential || !('rawId' in credential) || !('response' in credential)) {
      throw new Error('No passkey credential was created.');
    }

    const payload = toCredentialPayload(credential as PublicKeyCredential);
    const result = await this.postPasskeyChallenge<PasskeySessionResult>(
      PASSKEY_ENDPOINTS.registerVerify,
      {
        ...data,
        credential: payload,
      },
    );

    if (!result.success || !result.data?.token || !result.data.user) {
      throw new Error(result.message || 'Passkey registration failed.');
    }

    this.persistSession(result.data.token, result.data.user);
    return result.data;
  }

  async beginPasskeyAuthentication(data: PasskeyChallengeRequest = {}): Promise<PasskeyChallengeResponse['data']> {
    if (!this.isPasskeyBrowserSupported()) {
      throw new Error('Passkeys require a browser with WebAuthn support. Use email/password or Google sign-in as a fallback.');
    }

    if (!isSecureContext()) {
      throw new Error('Passkeys require HTTPS or localhost support. Use email/password or Google sign-in until the app is served securely.');
    }

    const response = await this.postPasskeyChallenge<PasskeyChallengeResponse>(
      PASSKEY_ENDPOINTS.loginOptions,
      data,
    );

    if (!response.success || !response.data?.challenge) {
      throw new Error(response.message || 'The backend did not return a valid passkey authentication challenge.');
    }

    return response.data;
  }

  async authenticateWithPasskey(data: PasskeyChallengeRequest = {}): Promise<PasskeySessionResult['data']> {
    const challenge = await this.beginPasskeyAuthentication(data);
    const credential = await navigator.credentials.get({
      publicKey: {
        ...challenge,
        challenge: base64UrlToArrayBuffer(challenge.challenge),
        allowCredentials: challenge.allowCredentials?.map((item) => ({
          ...item,
          id: base64UrlToArrayBuffer(item.id),
        })),
      } as PublicKeyCredentialRequestOptions,
    });

    if (!credential || !('rawId' in credential) || !('response' in credential)) {
      throw new Error('No passkey credential was returned by the browser.');
    }

    const payload = toCredentialPayload(credential as PublicKeyCredential);
    const result = await this.postPasskeyChallenge<PasskeySessionResult>(
      PASSKEY_ENDPOINTS.loginVerify,
      {
        ...data,
        credential: payload,
      },
    );

    if (!result.success || !result.data?.token || !result.data.user) {
      throw new Error(result.message || 'Passkey authentication failed.');
    }

    this.persistSession(result.data.token, result.data.user);
    return result.data;
  }

  /**
   * Performs a logout by invalidating the session on the backend and
   * clearing all local authentication state.
   * Does NOT throw on backend errors; swallows network error so client cleanup always succeeds.
   *
   * @returns Promise resolving to void when logout cleanup completes.
   *
   * @example
   * ```ts
   * import { authService } from '@/services/auth.service';
   *
   * await authService.logout();
   * console.log('User logged out, isAuthenticated:', authService.isAuthenticated()); // false
   * ```
   */
  async logout(): Promise<void> {
    try {
      await apiService.logout();
    } catch (error) {
      console.error('AuthService.logout failed:', error);
    } finally {
      this.clearSession();
    }
  }

  /**
   * Checks if the user is currently authenticated locally by inspecting localStorage for `auth_token`.
   * Synchronous operation; returns `false` in Server-Side Rendering (SSR) environment.
   *
   * @returns Boolean `true` if an auth token is stored in localStorage, `false` otherwise.
   */
  isAuthenticated(): boolean {
    if (typeof window === 'undefined') return false;
    return !!localStorage.getItem('auth_token');
  }

  /**
   * Gets the stored access token from browser localStorage.
   * Synchronous operation; returns `null` if window is undefined or token is missing.
   *
   * @returns JWT token string if found, or `null`.
   */
  getAccessToken(): string | null {
    if (typeof window === 'undefined') return null;
    return localStorage.getItem('auth_token');
  }

  /**
   * Gets and parses stored user data object from browser localStorage.
   * Synchronous operation; returns `null` if window is undefined or data is missing/invalid.
   *
   * @template T - Target return type (defaults to any).
   * @returns Parsed user object of type T or `null`.
   */
  getUserData<T = unknown>(): T | null {
    if (typeof window === 'undefined') return null;
    const data = localStorage.getItem('user_data');
    return data ? JSON.parse(data) : null;
  }
}

export const authService = new AuthService();
export default authService;
