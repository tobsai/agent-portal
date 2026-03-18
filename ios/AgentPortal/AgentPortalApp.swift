// AgentPortalApp.swift
// Agent Portal — iOS
//
// App entry point.
//
// Auth flow:
//   - Shows LoginView if the user is not authenticated (no token in Keychain).
//   - On successful Google OAuth, the portal deep-links back:
//       com.mapletree.agent-portal://auth/callback?token=<jwt>
//     `onOpenURL` hands this to AuthManager.handleCallback(url:).
//   - Once authenticated, ChannelManager boots to resolve the DM channel ID
//     so ChannelSSEManager can subscribe without delay.
//
// URL scheme registration:
//   The custom URL scheme `com.mapletree.agent-portal` must be registered in
//   the Xcode target's Info tab under "URL Types" for onOpenURL to fire.

import SwiftUI

@main
struct AgentPortalApp: App {

    @StateObject private var authManager = AuthManager.shared
    @StateObject private var channelManager = ChannelManager.shared

    var body: some Scene {
        WindowGroup {
            Group {
                if authManager.isAuthenticated {
                    ContentView()
                        .environmentObject(channelManager)
                        .environmentObject(authManager)
                } else {
                    LoginView()
                        .environmentObject(authManager)
                }
            }
            .onOpenURL { url in
                handleDeepLink(url: url)
            }
            .onChange(of: authManager.isAuthenticated) { _, isAuthenticated in
                if isAuthenticated {
                    // User just signed in — boot the channel manager.
                    ChannelManager.shared.boot()
                } else {
                    // User signed out — reset channel state and disconnect SSE.
                    ChannelManager.shared.reset()
                    ChannelSSEManager.shared.disconnect()
                }
            }
        }
    }

    // MARK: - Deep link handling

    private func handleDeepLink(url: URL) {
        // Handle OAuth callback from portal server.
        let handled = authManager.handleCallback(url: url)
        if handled {
            // ChannelManager.boot() will fire via .onChange(of: isAuthenticated) above.
            return
        }

        // Other deep-link schemes can be handled here in future phases.
        print("[AgentPortalApp] Unhandled deep link: \(url)")
    }
}
