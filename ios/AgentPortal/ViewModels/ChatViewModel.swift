// ChatViewModel.swift
// Agent Portal — iOS
//
// View model for the main chat view.
//
// Transport: ChannelSSEManager (portal SSE) for inbound + APIService.sendMessage() for outbound.
// WebSocketManager has been removed entirely (Phase 2c cleanup).

import Foundation
import Combine

@MainActor
final class ChatViewModel: ObservableObject {

    // MARK: Published state

    @Published var messages: [ChatMessage] = []
    @Published var pendingDelta: String = ""  // streaming partial text
    @Published var isTyping: Bool = false
    @Published var sendError: Error? = nil
    @Published var connectionState: ChannelSSEManager.ConnectionState = .disconnected

    // MARK: Dependencies

    private let sseManager = ChannelSSEManager.shared
    private let channelManager = ChannelManager.shared

    // MARK: Private

    private var cancellables = Set<AnyCancellable>()
    private var currentDeltaMessageId: String? = nil

    // MARK: - Init

    init() {
        bind()
    }

    // MARK: - Binding

    private func bind() {
        // Connect SSE once the channel ID is ready
        channelManager.$channelId
            .compactMap { $0 }
            .removeDuplicates()
            .sink { [weak self] channelId in
                self?.sseManager.connect(channelId: channelId)
            }
            .store(in: &cancellables)

        // Mirror SSE connection state
        sseManager.$connectionState
            .receive(on: DispatchQueue.main)
            .assign(to: \.connectionState, on: self)
            .store(in: &cancellables)

        // Typing indicator
        sseManager.$isTyping
            .receive(on: DispatchQueue.main)
            .assign(to: \.isTyping, on: self)
            .store(in: &cancellables)

        // Streaming delta — accumulate into pendingDelta
        sseManager.$lastDelta
            .compactMap { $0 }
            .receive(on: DispatchQueue.main)
            .sink { [weak self] delta in
                guard let self else { return }
                if self.currentDeltaMessageId == nil || self.currentDeltaMessageId == delta.messageId {
                    self.currentDeltaMessageId = delta.messageId
                    self.pendingDelta += delta.text
                } else {
                    // New message started — flush previous delta
                    self.flushDelta()
                    self.currentDeltaMessageId = delta.messageId
                    self.pendingDelta = delta.text
                }
            }
            .store(in: &cancellables)

        // Complete message — flush any pending delta, add to messages list
        sseManager.$lastMessage
            .compactMap { $0 }
            .receive(on: DispatchQueue.main)
            .sink { [weak self] event in
                guard let self else { return }
                self.flushDelta()
                let msg = ChatMessage(
                    id: event.id,
                    channelId: event.channelId,
                    content: event.content,
                    senderType: event.senderType,
                    senderName: event.senderName,
                    senderEmoji: event.senderEmoji,
                    createdAt: event.createdAt
                )
                self.messages.append(msg)
            }
            .store(in: &cancellables)
    }

    // MARK: - Send

    /// Send a user message.  Optimistically appends to `messages` before the server confirms.
    func send(content: String) {
        guard !content.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        guard let channelId = channelManager.channelId else {
            sendError = APIError.missingField("dmChannelId")
            return
        }

        // Optimistic message
        let optimistic = ChatMessage(
            id: UUID().uuidString,
            channelId: channelId,
            content: content,
            senderType: "user",
            senderName: "You",
            senderEmoji: "",
            createdAt: ISO8601DateFormatter().string(from: Date())
        )
        messages.append(optimistic)
        sendError = nil

        Task {
            do {
                try await APIService.shared.sendMessage(channelId: channelId, content: content)
            } catch {
                // Remove the optimistic message on failure
                messages.removeAll { $0.id == optimistic.id }
                sendError = error
            }
        }
    }

    // MARK: - Helpers

    private func flushDelta() {
        guard !pendingDelta.isEmpty else { return }
        if let id = currentDeltaMessageId {
            // If there's already a message with this ID, update it in-place
            if let idx = messages.firstIndex(where: { $0.id == id }) {
                messages[idx] = ChatMessage(
                    id: messages[idx].id,
                    channelId: messages[idx].channelId,
                    content: pendingDelta,
                    senderType: messages[idx].senderType,
                    senderName: messages[idx].senderName,
                    senderEmoji: messages[idx].senderEmoji,
                    createdAt: messages[idx].createdAt
                )
            } else {
                // No matching message yet — create one from the accumulated delta
                let msg = ChatMessage(
                    id: id,
                    channelId: channelManager.channelId ?? "",
                    content: pendingDelta,
                    senderType: "agent",
                    senderName: "Lewis",
                    senderEmoji: "📚",
                    createdAt: ISO8601DateFormatter().string(from: Date())
                )
                messages.append(msg)
            }
        }
        pendingDelta = ""
        currentDeltaMessageId = nil
    }
}

// MARK: - ChatMessage model

struct ChatMessage: Identifiable, Equatable {
    let id: String
    let channelId: String
    let content: String
    let senderType: String  // "user" | "agent"
    let senderName: String
    let senderEmoji: String
    let createdAt: String
}
