// ChannelSSEManager.swift
// Agent Portal — iOS
//
// SSE client that subscribes to GET /api/channels/:id/stream and publishes
// incoming server-sent events to the rest of the app.
//
// Architecture
// ───────────
//   • Uses URLSession + URLSessionDataDelegate for streaming (no third-party deps)
//   • Parses SSE events: `event: delta`, `event: message`, `event: typing`
//   • Publishes via @Published properties consumed by ChatViewModel
//   • Reconnects with exponential back-off (1s → 30s) on network failure
//   • Channel ID sourced from ChannelManager.shared (which reads UserDefaults)
//   • Authenticates via Bearer token from UserDefaults["sessionToken"]
//
// Migration note
// ──────────────
//   WebSocketManager has been removed entirely in Phase 2c.
//   This class is now the sole transport layer for agent messages on iOS.
//   Token is sourced from AuthManager (Keychain), not UserDefaults.

import Foundation
import Combine

// MARK: - Event models

struct SSEDelta {
    let text: String
    let messageId: String?
}

struct SSEMessage {
    let id: String
    let channelId: String
    let content: String
    let senderType: String
    let senderName: String
    let senderEmoji: String
    let createdAt: String
}

struct SSETyping {
    let agentId: String
    let channelId: String
}

// MARK: - ChannelSSEManager

@MainActor
final class ChannelSSEManager: NSObject, ObservableObject {

    static let shared = ChannelSSEManager()
    private override init() { super.init() }

    // MARK: Published streams

    @Published var lastDelta: SSEDelta?
    @Published var lastMessage: SSEMessage?
    @Published var isTyping: Bool = false
    @Published var connectionState: ConnectionState = .disconnected

    enum ConnectionState: Equatable {
        case disconnected
        case connecting
        case connected
        case failed(String)
    }

    // MARK: Private state

    private var urlSession: URLSession?
    private var dataTask: URLSessionDataTask?
    private var buffer: String = ""

    private var reconnectDelay: TimeInterval = 1
    private let maxReconnectDelay: TimeInterval = 30
    private var reconnectTask: Task<Void, Never>?
    private var currentChannelId: String?

    // MARK: - Public interface

    /// Start streaming the given channel. Safe to call multiple times —
    /// re-connects if the channel ID changed, no-ops if already connected to the same channel.
    func connect(channelId: String) {
        guard channelId != currentChannelId || connectionState == .disconnected else { return }
        disconnect()
        currentChannelId = channelId
        reconnectDelay = 1
        startStream(channelId: channelId)
    }

    /// Disconnect and cancel any pending reconnect.
    func disconnect() {
        reconnectTask?.cancel()
        reconnectTask = nil
        dataTask?.cancel()
        dataTask = nil
        urlSession?.invalidateAndCancel()
        urlSession = nil
        buffer = ""
        connectionState = .disconnected
        currentChannelId = nil
    }

    // MARK: - Private stream setup

    private func startStream(channelId: String) {
        // Read token from Keychain via AuthManager — not UserDefaults.
        guard let token = AuthManager.shared.sessionToken else {
            connectionState = .failed("No session token — please sign in")
            return
        }

        let baseURL = UserDefaults.standard.string(forKey: "portalBaseURL") ?? "https://talos.mtree.io"
        guard let url = URL(string: "\(baseURL)/api/channels/\(channelId)/stream") else {
            connectionState = .failed("Bad URL")
            return
        }

        var request = URLRequest(url: url, timeoutInterval: .infinity)
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("text/event-stream", forHTTPHeaderField: "Accept")
        request.setValue("no-cache", forHTTPHeaderField: "Cache-Control")

        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = .infinity
        config.timeoutIntervalForResource = .infinity

        urlSession = URLSession(configuration: config, delegate: self, delegateQueue: nil)
        dataTask = urlSession?.dataTask(with: request)
        connectionState = .connecting
        buffer = ""
        dataTask?.resume()
    }

    // MARK: - SSE Parsing

    private func processBuffer() {
        // SSE events are separated by double newlines (\n\n)
        let events = buffer.components(separatedBy: "\n\n")

        // Keep the last potentially incomplete chunk in the buffer
        buffer = events.last ?? ""

        let completeEvents = events.dropLast()
        for rawEvent in completeEvents where !rawEvent.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            parseAndDispatch(rawEvent)
        }
    }

    private func parseAndDispatch(_ raw: String) {
        var eventType = "message"
        var dataLines: [String] = []

        for line in raw.split(separator: "\n", omittingEmptySubsequences: false).map(String.init) {
            if line.hasPrefix("event:") {
                eventType = String(line.dropFirst(6)).trimmingCharacters(in: .whitespaces)
            } else if line.hasPrefix("data:") {
                dataLines.append(String(line.dropFirst(5)).trimmingCharacters(in: .whitespaces))
            }
            // ignore `id:` and `retry:` lines for now
        }

        let dataString = dataLines.joined(separator: "\n")
        guard !dataString.isEmpty,
              let jsonData = dataString.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any]
        else { return }

        DispatchQueue.main.async { [weak self] in
            self?.dispatch(eventType: eventType, json: json)
        }
    }

    private func dispatch(eventType: String, json: [String: Any]) {
        switch eventType {
        case "delta":
            let text = json["text"] as? String ?? ""
            let messageId = json["messageId"] as? String
            lastDelta = SSEDelta(text: text, messageId: messageId)

        case "message":
            guard
                let id = json["id"] as? String,
                let channelId = json["channel_id"] as? String,
                let content = json["content"] as? String
            else { return }
            lastMessage = SSEMessage(
                id: id,
                channelId: channelId,
                content: content,
                senderType: json["sender_type"] as? String ?? "",
                senderName: json["sender_name"] as? String ?? "",
                senderEmoji: json["sender_emoji"] as? String ?? "",
                createdAt: json["created_at"] as? String ?? ""
            )
            // Clear typing indicator when a complete message arrives
            isTyping = false

        case "typing":
            isTyping = true
            // Auto-clear after 3s if no further typing events
            Task { @MainActor in
                try? await Task.sleep(nanoseconds: 3_000_000_000)
                self.isTyping = false
            }

        default:
            break
        }
    }

    // MARK: - Reconnect logic

    private func scheduleReconnect(channelId: String) {
        let delay = reconnectDelay
        reconnectDelay = min(reconnectDelay * 2, maxReconnectDelay)

        reconnectTask = Task { [weak self] in
            guard let self else { return }
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            guard !Task.isCancelled else { return }
            await MainActor.run {
                self.buffer = ""
                self.startStream(channelId: channelId)
            }
        }
    }
}

// MARK: - URLSessionDataDelegate

extension ChannelSSEManager: URLSessionDataDelegate {

    nonisolated func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            completionHandler(.cancel)
            let code = (response as? HTTPURLResponse)?.statusCode ?? -1
            Task { @MainActor [weak self] in
                self?.connectionState = .failed("HTTP \(code)")
            }
            return
        }
        completionHandler(.allow)
        Task { @MainActor [weak self] in
            self?.connectionState = .connected
            self?.reconnectDelay = 1  // reset back-off on successful connect
        }
    }

    nonisolated func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        guard let text = String(data: data, encoding: .utf8) else { return }
        Task { @MainActor [weak self] in
            self?.buffer += text
            self?.processBuffer()
        }
    }

    nonisolated func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        let channelId = task.currentRequest?.url?.pathComponents
            .dropLast()  // "stream"
            .last        // channel UUID
        Task { @MainActor [weak self] in
            guard let self, let channelId = channelId, !channelId.isEmpty else { return }
            if let err = error as? URLError, err.code == .cancelled {
                // Intentional disconnect — don't reconnect
                self.connectionState = .disconnected
                return
            }
            let msg = error?.localizedDescription ?? "Stream closed"
            self.connectionState = .failed(msg)
            self.scheduleReconnect(channelId: channelId)
        }
    }
}
