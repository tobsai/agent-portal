// ContentView.swift
// Agent Portal — iOS
//
// Main chat interface. Pure SwiftUI, no network or auth logic.
// All state is sourced from ChatViewModel (via @StateObject).
//
// Layout:
//   ┌─────────────────────────────────┐
//   │  [Connection banner — if needed]│
//   │                                 │
//   │  Chat bubble list (ScrollView)  │
//   │                                 │
//   │  [Input bar + Send button]      │
//   └─────────────────────────────────┘

import SwiftUI

struct ContentView: View {

    @StateObject private var chatViewModel = ChatViewModel()
    @State private var inputText: String = ""
    @State private var scrollProxy: ScrollViewProxy? = nil

    var body: some View {
        VStack(spacing: 0) {
            connectionBanner
            messageList
            inputBar
        }
        .background(Color(.systemBackground))
        .onChange(of: chatViewModel.messages.count) { _, _ in
            scrollToBottom()
        }
        .onChange(of: chatViewModel.pendingDelta) { _, _ in
            scrollToBottom()
        }
        .onChange(of: chatViewModel.isTyping) { _, newValue in
            if newValue { scrollToBottom() }
        }
    }

    // MARK: - Connection Banner

    @ViewBuilder
    private var connectionBanner: some View {
        switch chatViewModel.connectionState {
        case .connected:
            EmptyView()
        case .connecting:
            bannerView(text: "Connecting…", color: .orange)
        case .disconnected:
            bannerView(text: "Disconnected — tap to retry", color: .gray)
        case .failed(let reason):
            bannerView(text: "Connection failed: \(reason)", color: .red)
        }
    }

    private func bannerView(text: String, color: Color) -> some View {
        HStack(spacing: 6) {
            if chatViewModel.connectionState == .connecting {
                ProgressView()
                    .scaleEffect(0.7)
                    .tint(.white)
            }
            Text(text)
                .font(.caption)
                .foregroundColor(.white)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
        .background(color)
        .transition(.move(edge: .top).combined(with: .opacity))
        .animation(.easeInOut(duration: 0.3), value: chatViewModel.connectionState)
    }

    // MARK: - Message List

    private var messageList: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 12) {
                    ForEach(chatViewModel.messages) { message in
                        ChatBubbleView(message: message)
                            .id(message.id)
                    }

                    // Streaming delta bubble
                    if !chatViewModel.pendingDelta.isEmpty {
                        StreamingBubbleView(text: chatViewModel.pendingDelta)
                            .id("pendingDelta")
                    }

                    // Typing indicator
                    if chatViewModel.isTyping && chatViewModel.pendingDelta.isEmpty {
                        TypingIndicatorView()
                            .id("typingIndicator")
                    }

                    // Invisible anchor for scrolling
                    Color.clear
                        .frame(height: 1)
                        .id("bottomAnchor")
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
            }
            .onAppear {
                scrollProxy = proxy
                scrollToBottom()
            }
        }
    }

    // MARK: - Input Bar

    private var inputBar: some View {
        VStack(spacing: 0) {
            Divider()
            HStack(alignment: .bottom, spacing: 10) {
                TextField("Message Lewis…", text: $inputText, axis: .vertical)
                    .lineLimit(1...5)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 10)
                    .background(Color(.secondarySystemBackground))
                    .clipShape(RoundedRectangle(cornerRadius: 20))
                    .onSubmit {
                        submitIfValid()
                    }

                Button(action: submitIfValid) {
                    Image(systemName: "arrow.up.circle.fill")
                        .font(.system(size: 32))
                        .foregroundColor(canSend ? .accentColor : Color(.systemGray4))
                }
                .disabled(!canSend)
                .animation(.easeInOut(duration: 0.15), value: canSend)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
            .background(Color(.systemBackground))
        }
    }

    // MARK: - Helpers

    private var canSend: Bool {
        !inputText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    private func submitIfValid() {
        let trimmed = inputText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        chatViewModel.send(content: trimmed)
        inputText = ""
    }

    private func scrollToBottom() {
        withAnimation(.easeOut(duration: 0.2)) {
            scrollProxy?.scrollTo("bottomAnchor", anchor: .bottom)
        }
    }
}

// MARK: - ChatBubbleView

private struct ChatBubbleView: View {

    let message: ChatMessage

    private var isUser: Bool { message.senderType == "user" }

    var body: some View {
        HStack(alignment: .bottom, spacing: 8) {
            if isUser { Spacer(minLength: 48) }

            if !isUser {
                avatarView
            }

            VStack(alignment: isUser ? .trailing : .leading, spacing: 3) {
                if !isUser {
                    Text(senderLabel)
                        .font(.caption2)
                        .foregroundColor(.secondary)
                        .padding(.leading, 4)
                }

                Text(message.content)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 10)
                    .background(isUser ? Color.accentColor : Color(.secondarySystemBackground))
                    .foregroundColor(isUser ? .white : .primary)
                    .clipShape(BubbleShape(isUser: isUser))
            }

            if !isUser { Spacer(minLength: 48) }
        }
        .frame(maxWidth: .infinity, alignment: isUser ? .trailing : .leading)
    }

    private var senderLabel: String {
        let emoji = message.senderEmoji.isEmpty ? "" : "\(message.senderEmoji) "
        return "\(emoji)\(message.senderName)"
    }

    private var avatarView: some View {
        Text(message.senderEmoji.isEmpty ? "🤖" : message.senderEmoji)
            .font(.system(size: 20))
            .frame(width: 32, height: 32)
            .background(Color(.tertiarySystemBackground))
            .clipShape(Circle())
    }
}

// MARK: - StreamingBubbleView

private struct StreamingBubbleView: View {

    let text: String

    var body: some View {
        HStack(alignment: .bottom, spacing: 8) {
            Text("📚")
                .font(.system(size: 20))
                .frame(width: 32, height: 32)
                .background(Color(.tertiarySystemBackground))
                .clipShape(Circle())

            Text(text)
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
                .background(Color(.secondarySystemBackground))
                .foregroundColor(.primary)
                .clipShape(BubbleShape(isUser: false))
                .opacity(0.85)

            Spacer(minLength: 48)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

// MARK: - TypingIndicatorView

private struct TypingIndicatorView: View {

    @State private var phase: Int = 0

    private let timer = Timer.publish(every: 0.4, on: .main, in: .common).autoconnect()

    var body: some View {
        HStack(alignment: .bottom, spacing: 8) {
            Text("📚")
                .font(.system(size: 20))
                .frame(width: 32, height: 32)
                .background(Color(.tertiarySystemBackground))
                .clipShape(Circle())

            HStack(spacing: 4) {
                ForEach(0..<3, id: \.self) { index in
                    Circle()
                        .fill(Color(.systemGray3))
                        .frame(width: 8, height: 8)
                        .scaleEffect(phase == index ? 1.3 : 0.85)
                        .animation(.easeInOut(duration: 0.3), value: phase)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 14)
            .background(Color(.secondarySystemBackground))
            .clipShape(BubbleShape(isUser: false))

            Spacer(minLength: 48)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .onReceive(timer) { _ in
            phase = (phase + 1) % 3
        }
    }
}

// MARK: - BubbleShape

private struct BubbleShape: Shape {

    let isUser: Bool

    func path(in rect: CGRect) -> Path {
        let radius: CGFloat = 18
        let tailSize: CGFloat = 6

        var path = Path()

        if isUser {
            // Rounded rect with bottom-right flat corner (tail side)
            path.move(to: CGPoint(x: rect.minX + radius, y: rect.minY))
            path.addLine(to: CGPoint(x: rect.maxX - radius, y: rect.minY))
            path.addArc(center: CGPoint(x: rect.maxX - radius, y: rect.minY + radius),
                        radius: radius, startAngle: .degrees(-90), endAngle: .degrees(0), clockwise: false)
            path.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY - tailSize))
            path.addLine(to: CGPoint(x: rect.maxX + tailSize, y: rect.maxY))
            path.addLine(to: CGPoint(x: rect.minX + radius, y: rect.maxY))
            path.addArc(center: CGPoint(x: rect.minX + radius, y: rect.maxY - radius),
                        radius: radius, startAngle: .degrees(90), endAngle: .degrees(180), clockwise: false)
            path.addLine(to: CGPoint(x: rect.minX, y: rect.minY + radius))
            path.addArc(center: CGPoint(x: rect.minX + radius, y: rect.minY + radius),
                        radius: radius, startAngle: .degrees(180), endAngle: .degrees(270), clockwise: false)
        } else {
            // Rounded rect with bottom-left flat corner (tail side)
            path.move(to: CGPoint(x: rect.minX + radius, y: rect.minY))
            path.addLine(to: CGPoint(x: rect.maxX - radius, y: rect.minY))
            path.addArc(center: CGPoint(x: rect.maxX - radius, y: rect.minY + radius),
                        radius: radius, startAngle: .degrees(-90), endAngle: .degrees(0), clockwise: false)
            path.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY - radius))
            path.addArc(center: CGPoint(x: rect.maxX - radius, y: rect.maxY - radius),
                        radius: radius, startAngle: .degrees(0), endAngle: .degrees(90), clockwise: false)
            path.addLine(to: CGPoint(x: rect.minX + tailSize, y: rect.maxY))
            path.addLine(to: CGPoint(x: rect.minX - tailSize, y: rect.maxY))
            path.addLine(to: CGPoint(x: rect.minX, y: rect.maxY - tailSize))
            path.addLine(to: CGPoint(x: rect.minX, y: rect.minY + radius))
            path.addArc(center: CGPoint(x: rect.minX + radius, y: rect.minY + radius),
                        radius: radius, startAngle: .degrees(180), endAngle: .degrees(270), clockwise: false)
        }

        path.closeSubpath()
        return path
    }
}

// MARK: - Preview

#Preview {
    ContentView()
}
