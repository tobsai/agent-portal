// AuthManager.swift
// Agent Portal — iOS
//
// Manages the authentication lifecycle for the portal session token.
//
// Design:
//   - Token is stored in the iOS Keychain (SecItem API), NOT UserDefaults.
//   - Exposes @Published `isAuthenticated` so any SwiftUI view can gate on auth state.
//   - Google OAuth is the primary (and only) auth flow: the portal server handles
//     the OAuth handshake and deep-links back with a JWT via the custom URL scheme:
//       com.mapletree.agent-portal://auth/callback?token=<jwt>
//   - `handleCallback(url:)` is called from the app's `onOpenURL` handler.
//   - `signOut()` clears the token from Keychain and resets auth state.
//
// Keychain key: "com.mapletree.agent-portal.sessionToken"
// Service name: "AgentPortal"

import Foundation
import Combine
import Security

@MainActor
final class AuthManager: ObservableObject {

    static let shared = AuthManager()
    private init() {
        // Restore authentication state from Keychain on init.
        _isAuthenticated = readTokenFromKeychain() != nil
    }

    // MARK: - Published state

    @Published private(set) var isAuthenticated: Bool

    // MARK: - Constants

    private let keychainService = "AgentPortal"
    private let keychainAccount = "com.mapletree.agent-portal.sessionToken"

    // MARK: - Public interface

    /// Returns the current session token, or nil if not authenticated.
    /// All services that need the token should call this; nothing reads Keychain directly.
    var sessionToken: String? {
        readTokenFromKeychain()
    }

    /// Handle the OAuth callback deep-link from the portal server.
    ///
    /// Expected URL: `com.mapletree.agent-portal://auth/callback?token=<jwt>`
    ///
    /// - Returns: `true` if the URL was a valid auth callback and the token was stored.
    @discardableResult
    func handleCallback(url: URL) -> Bool {
        guard
            url.scheme == "com.mapletree.agent-portal",
            url.host == "auth",
            url.pathComponents.contains("callback"),
            let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
            let tokenItem = components.queryItems?.first(where: { $0.name == "token" }),
            let token = tokenItem.value,
            !token.isEmpty
        else {
            return false
        }

        do {
            try storeToken(token)
            isAuthenticated = true
            return true
        } catch {
            print("[AuthManager] Failed to store token in Keychain: \(error)")
            return false
        }
    }

    /// Sign the user out: clear the token from Keychain and reset state.
    /// `ChannelManager` and `ChannelSSEManager` should be disconnected by the caller
    /// before invoking this method.
    func signOut() {
        deleteTokenFromKeychain()
        isAuthenticated = false
    }

    // MARK: - OAuth initiation

    /// Returns the URL to open in Safari/ASWebAuthenticationSession to initiate Google OAuth.
    func googleOAuthURL(portalBaseURL: URL) -> URL {
        portalBaseURL.appendingPathComponent("/auth/google")
    }

    // MARK: - Keychain helpers

    private func storeToken(_ token: String) throws {
        guard let data = token.data(using: .utf8) else {
            throw AuthError.tokenEncodingFailed
        }

        // Delete any existing item first (SecItemAdd fails if item already exists).
        deleteTokenFromKeychain()

        let query: [CFString: Any] = [
            kSecClass:       kSecClassGenericPassword,
            kSecAttrService: keychainService,
            kSecAttrAccount: keychainAccount,
            kSecValueData:   data,
            // Accessible after first unlock so background token reads work.
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlock,
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw AuthError.keychainWriteFailed(status: status)
        }
    }

    private func readTokenFromKeychain() -> String? {
        let query: [CFString: Any] = [
            kSecClass:            kSecClassGenericPassword,
            kSecAttrService:      keychainService,
            kSecAttrAccount:      keychainAccount,
            kSecReturnData:       true,
            kSecMatchLimit:       kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess,
              let data = result as? Data,
              let token = String(data: data, encoding: .utf8),
              !token.isEmpty
        else {
            return nil
        }

        return token
    }

    private func deleteTokenFromKeychain() {
        let query: [CFString: Any] = [
            kSecClass:       kSecClassGenericPassword,
            kSecAttrService: keychainService,
            kSecAttrAccount: keychainAccount,
        ]
        SecItemDelete(query as CFDictionary)
    }
}

// MARK: - Errors

enum AuthError: Error, LocalizedError {
    case tokenEncodingFailed
    case keychainWriteFailed(status: OSStatus)

    var errorDescription: String? {
        switch self {
        case .tokenEncodingFailed:
            return "Failed to encode session token for Keychain storage."
        case .keychainWriteFailed(let status):
            return "Keychain write failed (OSStatus \(status))."
        }
    }
}
