import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import authService from '../auth.service';
import apiService from '../api';

describe('AuthService', () => {
  let navigatorCredentialsDescriptor: PropertyDescriptor | undefined;
  let secureContextDescriptor: PropertyDescriptor | undefined;
  let publicKeyCredentialDescriptor: PropertyDescriptor | undefined;

  beforeEach(() => {
    authService.clearRecentAuthentication();
    // Clear localStorage before each test
    if (typeof window !== 'undefined') {
      localStorage.clear();
    }
  });

  afterEach(() => {
    authService.clearRecentAuthentication();
    if (typeof window !== 'undefined') {
      localStorage.clear();
    }
    vi.unstubAllGlobals();
    if (typeof navigator !== 'undefined') {
      if (navigatorCredentialsDescriptor) {
        Object.defineProperty(navigator, 'credentials', navigatorCredentialsDescriptor);
      } else {
        delete (navigator as Navigator & { credentials?: CredentialsContainer }).credentials;
      }
    }
    if (typeof window !== 'undefined') {
      if (secureContextDescriptor) {
        Object.defineProperty(window, 'isSecureContext', secureContextDescriptor);
      } else {
        delete (window as Window & { isSecureContext?: boolean }).isSecureContext;
      }
      if (publicKeyCredentialDescriptor) {
        Object.defineProperty(window, 'PublicKeyCredential', publicKeyCredentialDescriptor);
      } else {
        delete (window as Window & { PublicKeyCredential?: typeof PublicKeyCredential }).PublicKeyCredential;
      }
    }
    navigatorCredentialsDescriptor = undefined;
    secureContextDescriptor = undefined;
    publicKeyCredentialDescriptor = undefined;
  });

  describe('reauthenticate', () => {
    it('grants recent authentication only after backend verification succeeds', async () => {
      const verifyCredentials = vi
        .spyOn(apiService, 'reauthenticate')
        .mockResolvedValue();

      await authService.reauthenticate('test@example.com', 'current-password');

      expect(verifyCredentials).toHaveBeenCalledWith(
        'test@example.com',
        'current-password',
      );
      expect(authService.hasRecentAuthentication()).toBe(true);
    });

    it('does not grant access when the backend rejects the credentials', async () => {
      vi.spyOn(apiService, 'reauthenticate').mockRejectedValue(
        new Error('Invalid credentials'),
      );

      await expect(
        authService.reauthenticate('test@example.com', 'wrong-password'),
      ).rejects.toThrow('Invalid credentials');
      expect(authService.hasRecentAuthentication()).toBe(false);
    });

    it('expires the grant after five minutes', async () => {
      let now = 1_000;
      vi.spyOn(Date, 'now').mockImplementation(() => now);
      vi.spyOn(apiService, 'reauthenticate').mockResolvedValue();

      await authService.reauthenticate('test@example.com', 'current-password');
      expect(authService.hasRecentAuthentication()).toBe(true);

      now += 5 * 60 * 1000;
      expect(authService.hasRecentAuthentication()).toBe(false);
    });

    it('clears the grant when the user cancels the protected action', async () => {
      vi.spyOn(apiService, 'reauthenticate').mockResolvedValue();
      await authService.reauthenticate('test@example.com', 'current-password');

      authService.clearRecentAuthentication();

      expect(authService.hasRecentAuthentication()).toBe(false);
    });
  });

  describe('isAuthenticated', () => {
    it('returns false when no token is stored', () => {
      expect(authService.isAuthenticated()).toBe(false);
    });

    it('returns true when token is stored in localStorage', () => {
      if (typeof window !== 'undefined') {
        localStorage.setItem('auth_token', 'test-token');
      }
      expect(authService.isAuthenticated()).toBe(true);
    });

    it('returns false in SSR environment', () => {
      const originalWindow = global.window;
      // @ts-expect-error - Simulating SSR
      delete global.window;
      expect(authService.isAuthenticated()).toBe(false);
      global.window = originalWindow;
    });
  });

  describe('getAccessToken', () => {
    it('returns null when no token is stored', () => {
      expect(authService.getAccessToken()).toBeNull();
    });

    it('returns token when stored in localStorage', () => {
      if (typeof window !== 'undefined') {
        localStorage.setItem('auth_token', 'test-token-123');
      }
      expect(authService.getAccessToken()).toBe('test-token-123');
    });

    it('returns null in SSR environment', () => {
      const originalWindow = global.window;
      // @ts-expect-error - Simulating SSR
      delete global.window;
      expect(authService.getAccessToken()).toBeNull();
      global.window = originalWindow;
    });
  });

  describe('getUserData', () => {
    it('returns null when no user data is stored', () => {
      expect(authService.getUserData()).toBeNull();
    });

    it('returns parsed user data when stored in localStorage', () => {
      const userData = { id: '123', email: 'test@example.com', name: 'Test User' };
      if (typeof window !== 'undefined') {
        localStorage.setItem('user_data', JSON.stringify(userData));
      }
      expect(authService.getUserData()).toEqual(userData);
    });

    it('returns null in SSR environment', () => {
      const originalWindow = global.window;
      // @ts-expect-error - Simulating SSR
      delete global.window;
      expect(authService.getUserData()).toBeNull();
      global.window = originalWindow;
    });

    it('returns typed data when generic type is specified', () => {
      interface UserData {
        id: string;
        email: string;
      }
      const userData: UserData = { id: '123', email: 'test@example.com' };
      if (typeof window !== 'undefined') {
        localStorage.setItem('user_data', JSON.stringify(userData));
      }
      const result = authService.getUserData<UserData>();
      expect(result?.email).toBe('test@example.com');
    });
  });

  describe('logout', () => {
    it('clears local state on logout', async () => {
      if (typeof window !== 'undefined') {
        localStorage.setItem('auth_token', 'test-token');
        localStorage.setItem('user_data', JSON.stringify({ id: '123' }));
      }

      await authService.logout();

      expect(authService.isAuthenticated()).toBe(false);
      expect(authService.getAccessToken()).toBeNull();
    });

    it('clears auth_token from localStorage', async () => {
      if (typeof window !== 'undefined') {
        localStorage.setItem('auth_token', 'test-token');
      }

      await authService.logout();

      expect(localStorage.getItem('auth_token')).toBeNull();
    });

    it('clears user_data from localStorage', async () => {
      if (typeof window !== 'undefined') {
        localStorage.setItem('user_data', JSON.stringify({ id: '123' }));
      }

      await authService.logout();

      expect(localStorage.getItem('user_data')).toBeNull();
    });

    it('clears refresh_token from localStorage if present', async () => {
      if (typeof window !== 'undefined') {
        localStorage.setItem('refresh_token', 'refresh-token');
      }

      await authService.logout();

      expect(localStorage.getItem('refresh_token')).toBeNull();
    });

    it('clears sessionStorage', async () => {
      if (typeof window !== 'undefined') {
        sessionStorage.setItem('test-key', 'test-value');
      }

      await authService.logout();

      expect(sessionStorage.length).toBe(0);
    });
  });

  describe('passkey support', () => {
    it('detects passkey support when WebAuthn APIs are available', () => {
      publicKeyCredentialDescriptor = Object.getOwnPropertyDescriptor(window, 'PublicKeyCredential');
      Object.defineProperty(window, 'PublicKeyCredential', {
        value: function PublicKeyCredential() {},
        configurable: true,
      });
      navigatorCredentialsDescriptor = Object.getOwnPropertyDescriptor(navigator, 'credentials');
      Object.defineProperty(window.navigator, 'credentials', {
        value: {},
        configurable: true,
      });

      expect(authService.isPasskeyBrowserSupported()).toBe(true);
    });

    it('throws a clear error when the passkey challenge endpoint rejects', async () => {
      publicKeyCredentialDescriptor = Object.getOwnPropertyDescriptor(window, 'PublicKeyCredential');
      Object.defineProperty(window, 'PublicKeyCredential', {
        value: function PublicKeyCredential() {},
        configurable: true,
      });
      navigatorCredentialsDescriptor = Object.getOwnPropertyDescriptor(navigator, 'credentials');
      Object.defineProperty(navigator, 'credentials', {
        value: {},
        configurable: true,
      });
      secureContextDescriptor = Object.getOwnPropertyDescriptor(window, 'isSecureContext');
      Object.defineProperty(window, 'isSecureContext', {
        value: true,
        configurable: true,
      });
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        json: async () => ({ message: 'Passkey route is not registered on the backend.' }),
      }));

      await expect(authService.beginPasskeyRegistration({ email: 'test@example.com' })).rejects.toThrow(
        'Passkey route is not registered on the backend.',
      );
    });

    it('completes a passkey login ceremony and stores the session token', async () => {
      publicKeyCredentialDescriptor = Object.getOwnPropertyDescriptor(window, 'PublicKeyCredential');
      Object.defineProperty(window, 'PublicKeyCredential', {
        value: function PublicKeyCredential() {},
        configurable: true,
      });
      secureContextDescriptor = Object.getOwnPropertyDescriptor(window, 'isSecureContext');
      Object.defineProperty(window, 'isSecureContext', {
        value: true,
        configurable: true,
      });
      navigatorCredentialsDescriptor = Object.getOwnPropertyDescriptor(navigator, 'credentials');

      const fakeCredential = {
        id: 'credential-id',
        rawId: new Uint8Array([1, 2, 3, 4]).buffer,
        type: 'public-key',
        response: {
          clientDataJSON: new Uint8Array([10, 11, 12]).buffer,
          authenticatorData: new Uint8Array([20, 21, 22]).buffer,
          signature: new Uint8Array([30, 31, 32]).buffer,
          userHandle: null,
        },
        getClientExtensionResults: () => ({}) as AuthenticationExtensionsClientOutputs,
      };

      Object.defineProperty(navigator, 'credentials', {
        value: {
          get: vi.fn().mockResolvedValue(fakeCredential),
        },
        configurable: true,
      });

      vi.stubGlobal('fetch', vi.fn()
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            success: true,
            message: 'Challenge ready',
            data: {
              challenge: 'AQIDBA==',
              rpId: 'localhost',
              allowCredentials: [{ type: 'public-key', id: 'AQID' }],
            },
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            success: true,
            message: 'Signed in',
            data: {
              token: 'passkey-session-token',
              user: {
                id: 'u1',
                email: 'test@example.com',
                name: 'Test User',
                address: 'G...',
                publicKey: 'G...',
                isDeployed: true,
                isFunded: true,
                tokenType: 'XLM',
                authProvider: 'passkey',
                isEmailVerified: true,
                createdAt: '2026-01-01T00:00:00Z',
                updatedAt: '2026-01-01T00:00:00Z',
              },
            },
          }),
        }));

      const result = await authService.authenticateWithPasskey({ email: 'test@example.com' });

      expect(result.token).toBe('passkey-session-token');
      expect(localStorage.getItem('auth_token')).toBe('passkey-session-token');
    });

    it('creates a passkey from backend-issued registration options', async () => {
      publicKeyCredentialDescriptor = Object.getOwnPropertyDescriptor(window, 'PublicKeyCredential');
      Object.defineProperty(window, 'PublicKeyCredential', {
        value: function PublicKeyCredential() {},
        configurable: true,
      });
      secureContextDescriptor = Object.getOwnPropertyDescriptor(window, 'isSecureContext');
      Object.defineProperty(window, 'isSecureContext', {
        value: true,
        configurable: true,
      });
      navigatorCredentialsDescriptor = Object.getOwnPropertyDescriptor(navigator, 'credentials');
      const fakeCredential = {
        id: 'credential-id',
        rawId: new Uint8Array([1, 2, 3, 4]).buffer,
        type: 'public-key',
        response: {
          clientDataJSON: new Uint8Array([10, 11, 12]).buffer,
          attestationObject: new Uint8Array([20, 21, 22]).buffer,
        },
        getClientExtensionResults: () => ({}),
      };
      const createCredential = vi.fn().mockResolvedValue(fakeCredential);

      Object.defineProperty(navigator, 'credentials', {
        value: { create: createCredential },
        configurable: true,
      });

      const fetchMock = vi.fn()
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            success: true,
            message: 'Challenge ready',
            data: {
              challenge: 'AQIDBA',
              rpId: 'localhost',
              rpName: 'ChenPilot',
              user: { id: 'BQYH', name: 'test@example.com', displayName: 'Test User' },
              pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
            },
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            success: true,
            message: 'Passkey registered',
            data: {
              token: 'passkey-registration-token',
              user: {
                id: 'u1',
                email: 'test@example.com',
                name: 'Test User',
                address: 'G...',
                publicKey: 'G...',
                isDeployed: true,
                isFunded: true,
                tokenType: 'XLM',
                authProvider: 'passkey',
                isEmailVerified: true,
                createdAt: '2026-01-01T00:00:00Z',
                updatedAt: '2026-01-01T00:00:00Z',
              },
            },
          }),
        });
      vi.stubGlobal('fetch', fetchMock);

      const result = await authService.registerWithPasskey({
        email: 'test@example.com',
        name: 'Test User',
      });

      expect(createCredential).toHaveBeenCalledOnce();
      const options = createCredential.mock.calls[0][0].publicKey;
      expect(Array.from(new Uint8Array(options.challenge))).toEqual([1, 2, 3, 4]);
      expect(Array.from(new Uint8Array(options.user.id))).toEqual([5, 6, 7]);
      expect(result.token).toBe('passkey-registration-token');
      expect(localStorage.getItem('auth_token')).toBe('passkey-registration-token');
    });
  });
});
