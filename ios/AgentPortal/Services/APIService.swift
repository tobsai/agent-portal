// APIService.swift
// Agent Portal — iOS
//
// Centralised HTTP client for the Agent Portal server.
// All network calls go through here; nothing in ViewModels talks to URLSession directly.

import Foundation

// MARK: - Errors

enum APIError: Error, LocalizedError {
    case notAuthenticated
    case httpError(statusCode: Int, body: String?)
    case decodingError(underlying: Error)
    case missingField(String)

    var errorDescription: String? {
        switch self {
        case .notAuthenticated:
            return "No session token — please log in."
        case .httpError(let code, let body):
            return "HTTP \(code): \(body ?? "(no body)")"
        case .decodingError(let err):
            return "Decode error: \(err.localizedDescription)"
        case .missingField(let name):
            return "Required field missing: \(name)"
        }
    }
}

// MARK: - Response Models

struct DMChannelResponse: Decodable {
    let id: String
    let name: String?
    let isDm: Bool?
    let dmAgentId: String?
    let agent: AgentRef?

    struct AgentRef: Decodable {
        let id: String
        let name: String
        let emoji: String?
    }

    enum CodingKeys: String, CodingKey {
        case id, name, agent
        case isDm = "is_dm"
        case dmAgentId = "dm_agent_id"
    }
}

struct SendMessageResponse: Decodable {
    let id: String
    let channelId: String?
    let content: String?

    enum CodingKeys: String, CodingKey {
        case id, content
        case channelId = "channel_id"
    }
}

struct UserProfile: Decodable {
    let id: String
    let name: String?
    let email: String?
}

// MARK: - APIService

/// Singleton HTTP client.  All methods are `async throws`.
/// Session token is stored in UserDefaults under `"sessionToken"`.
final class APIService {

    static let shared = APIService()
    private init() {}

    // MARK: Configuration

    private var baseURL: URL {
        // Allow override via UserDefaults for dev convenience.
        let stored = UserDefaults.standard.string(forKey: "portalBaseURL")
        let raw = stored ?? "https://talos.mtree.io"
        return URL(string: raw)!
    }

    private var sessionToken: String? {
        // Token is stored in Keychain via AuthManager, not UserDefaults.
        // AuthManager.shared is the single source of truth for the session token.
        AuthManager.shared.sessionToken
    }

    // MARK: - Auth helpers

    /// Returns the current authenticated user profile, or throws `.notAuthenticated`.
    func fetchUser() async throws -> UserProfile {
        let data = try await get(path: "/api/me")
        return try decode(UserProfile.self, from: data)
    }

    // MARK: - DM Channel

    /// Fetches (or creates) the DM channel between the authenticated user and `agentId`.
    /// Returns the channel UUID string.
    ///
    /// The caller is responsible for persisting the UUID via `UserDefaults` (key `"dmChannelId"`).
    func fetchDMChannel(agentId: String) async throws -> String {
        let data = try await get(path: "/api/dm/\(agentId)")
        let response = try decode(DMChannelResponse.self, from: data)
        return response.id
    }

    // MARK: - Messages

    /// Sends a user message to the given channel.
    /// This routes through `POST /api/channels/:id/messages`, which the server then
    /// delivers to the agent via the native gateway client (`sendUserMessage`).
    ///
    /// - Parameters:
    ///   - channelId: The UUID of the target channel (from `UserDefaults["dmChannelId"]`).
    ///   - content: Plain text message body.
    ///   - senderId: Authenticated user ID.  If nil, the server derives it from the session.
    @discardableResult
    func sendMessage(channelId: String, content: String, senderId: String? = nil) async throws -> SendMessageResponse {
        var body: [String: Any] = ["content": content]
        if let sid = senderId { body["senderId"] = sid }
        let data = try await post(path: "/api/channels/\(channelId)/messages", body: body)
        return try decode(SendMessageResponse.self, from: data)
    }

    // MARK: - Private HTTP primitives

    private func get(path: String) async throws -> Data {
        guard let token = sessionToken else { throw APIError.notAuthenticated }
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "GET"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        return try await perform(request)
    }

    private func post(path: String, body: [String: Any]) async throws -> Data {
        guard let token = sessionToken else { throw APIError.notAuthenticated }
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        return try await perform(request)
    }

    private func perform(_ request: URLRequest) async throws -> Data {
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw APIError.httpError(statusCode: -1, body: nil)
        }
        guard (200..<300).contains(http.statusCode) else {
            let body = String(data: data, encoding: .utf8)
            throw APIError.httpError(statusCode: http.statusCode, body: body)
        }
        return data
    }

    private func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        do {
            return try decoder.decode(type, from: data)
        } catch {
            throw APIError.decodingError(underlying: error)
        }
    }
}
