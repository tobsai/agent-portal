// LoginView.swift
// Agent Portal — iOS
//
// Shown when the user is not authenticated.  Initiates Google OAuth by opening
// the portal's `/auth/google` endpoint in Safari via `openURL`.
//
// Auth flow:
//   1. User taps "Sign in with Google"
//   2. Safari opens `https://talos.mtree.io/auth/google`
//   3. Portal server handles Google OAuth handshake
//   4. Server deep-links back: `com.mapletree.agent-portal://auth/callback?token=<jwt>`
//   5. `AgentPortalApp.onOpenURL` calls `AuthManager.shared.handleCallback(url:)`
//   6. `AuthManager.isAuthenticated` flips to `true` → LoginView dismissed automatically
//
// No email/password fields: the portal exclusively uses Google OAuth.
// The JWT issued by the server is stored in Keychain by `AuthManager`.

import SwiftUI

struct LoginView: View {

    @Environment(\.openURL) private var openURL
    @EnvironmentObject private var authManager: AuthManager

    /// Allow overriding the portal base URL for dev builds.
    private var portalBaseURL: URL {
        if let override = UserDefaults.standard.string(forKey: "portalBaseURL"),
           let url = URL(string: override) {
            return url
        }
        return URL(string: "https://talos.mtree.io")!
    }

    var body: some View {
        ZStack {
            Color(.systemBackground)
                .ignoresSafeArea()

            VStack(spacing: 40) {
                Spacer()

                // Logo + wordmark
                VStack(spacing: 12) {
                    Image(systemName: "bubble.left.and.bubble.right.fill")
                        .font(.system(size: 64))
                        .foregroundStyle(.tint)

                    Text("Agent Portal")
                        .font(.largeTitle.bold())

                    Text("Your direct line to Lewis")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }

                Spacer()

                // Sign-in button
                Button(action: signInWithGoogle) {
                    HStack(spacing: 12) {
                        Image(systemName: "globe")
                            .imageScale(.medium)
                        Text("Sign in with Google")
                            .fontWeight(.semibold)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 16)
                    .background(Color.accentColor)
                    .foregroundStyle(.white)
                    .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                }
                .padding(.horizontal, 32)

                // Footer note
                Text("Authentication is handled securely via Google.\nYour token is stored in the iOS Keychain.")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)

                Spacer().frame(height: 20)
            }
        }
    }

    // MARK: - Actions

    private func signInWithGoogle() {
        let oauthURL = authManager.googleOAuthURL(portalBaseURL: portalBaseURL)
        openURL(oauthURL)
    }
}

#Preview {
    LoginView()
        .environmentObject(AuthManager.shared)
}
