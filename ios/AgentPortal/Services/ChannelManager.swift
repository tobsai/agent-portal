// ChannelManager.swift
// Agent Portal — iOS
//
// Responsible for resolving and caching the DM channel ID on launch.
// Call `ChannelManager.shared.boot()` after the user is authenticated.
//
// Design notes:
//   - Guards on `AuthManager.isAuthenticated` before making any network calls.
//     If not authenticated, boot() is a no-op — AgentPortalApp gates UI on auth state.
//   - Uses UserDefaults for persistence (key: "dmChannelId", "dmChannelFetchedAt").
//     The channel UUID is not sensitive — only the session token (in Keychain) is.
//   - Re-fetches if cached value is >24h old or missing
//   - `channelId` is published so any observer can react once the value is ready
//   - Intentionally separate from `APIService` — single responsibility

import Foundation
import Combine

@MainActor
final class ChannelManager: ObservableObject {

    static let shared = ChannelManager()
    private init() {}

    // MARK: - Published state

    @Published private(set) var channelId: String? = nil
    @Published private(set) var isReady: Bool = false
    @Published private(set) var error: Error? = nil

    // MARK: - Configuration

    /// The agent ID whose DM channel we resolve on launch.
    private let agentId = "lewis"

    private enum UDKey {
        static let channelId    = "dmChannelId"
        static let fetchedAt    = "dmChannelFetchedAt"
    }

    private let maxCacheAge: TimeInterval = 24 * 60 * 60  // 24 hours

    // MARK: - Boot

    /// Called after authentication is confirmed.
    /// Resolves the DM channel ID, using the cache when fresh and fetching
    /// from the server when stale or missing.
    ///
    /// This is a no-op if the user is not authenticated — `AgentPortalApp`
    /// ensures `boot()` is only called from the authenticated code path.
    func boot() {
        guard AuthManager.shared.isAuthenticated else {
            // Not authenticated — nothing to resolve. The app will show LoginView.
            return
        }

        if let cached = cachedChannelId() {
            channelId = cached
            isReady = true
            return
        }

        Task {
            await refresh()
        }
    }

    /// Resets channel state on sign-out so the next login starts fresh.
    func reset() {
        channelId = nil
        isReady = false
        error = nil
        UserDefaults.standard.removeObject(forKey: UDKey.channelId)
        UserDefaults.standard.removeObject(forKey: UDKey.fetchedAt)
    }

    /// Force-refresh the channel ID from the server, regardless of cache age.
    func refresh() async {
        error = nil
        do {
            let id = try await APIService.shared.fetchDMChannel(agentId: agentId)
            persist(channelId: id)
            channelId = id
            isReady = true
        } catch {
            self.error = error
            // If we have a stale cached value, surface it so the app isn't blocked.
            if let stale = UserDefaults.standard.string(forKey: UDKey.channelId) {
                channelId = stale
                isReady = true
            }
        }
    }

    // MARK: - Cache helpers

    private func cachedChannelId() -> String? {
        guard
            let id = UserDefaults.standard.string(forKey: UDKey.channelId),
            !id.isEmpty,
            let fetchedAt = UserDefaults.standard.object(forKey: UDKey.fetchedAt) as? Date,
            Date().timeIntervalSince(fetchedAt) < maxCacheAge
        else {
            return nil
        }
        return id
    }

    private func persist(channelId: String) {
        UserDefaults.standard.set(channelId, forKey: UDKey.channelId)
        UserDefaults.standard.set(Date(), forKey: UDKey.fetchedAt)
    }
}
