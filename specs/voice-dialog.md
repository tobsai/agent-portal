# Voice Dialog — Agent Portal Feature Spec

## Overview
Add two-way voice conversation to Agent Portal (web + iOS). User taps a mic button, speaks, agent responds with audio — like Siri but through our portal.

## User Experience
1. User taps/clicks mic button in chat UI
2. Browser listens for speech (Web Speech API / native iOS)
3. On silence/pause, transcript sent as chat message
4. Agent processes and responds (text)
5. Response is converted to audio (ElevenLabs TTS) and played back
6. Loop continues until user stops

## Architecture

### Web (Agent Portal)
- **Input:** Web Speech API (`webkitSpeechRecognition`) for STT — works in Chrome/Edge, no API key needed
- **Transport:** Existing Socket.io WebSocket connection
- **Output:** New API endpoint `POST /api/tts` that accepts text, calls ElevenLabs, returns audio stream
- **UI:** Floating mic button in chat, visual states (listening/thinking/speaking)
- **Fallback:** If Web Speech API unavailable, show "Voice not supported in this browser"

### iOS (Agent Portal app)  
- **Option A:** Use same web implementation via WKWebView (requires mic permission in Info.plist)
- **Option B:** Native AVAudioSession + Speech framework for better latency
- **Start with Option A** — simpler, shared code

### API Endpoint
```
POST /api/tts
Headers: Authorization: Bearer <token>
Body: { "text": "response text", "voiceId": "JBFqnCBsd6RMkjVDRZzb" }
Response: audio/mpeg stream
```

### Config
- ElevenLabs API key: from env `ELEVENLABS_API_KEY` 
- Voice ID: `JBFqnCBsd6RMkjVDRZzb` (George)
- Model: `eleven_multilingual_v2`

## UI Components
- `VoiceButton` — mic toggle with states: idle, listening, thinking, speaking
- Visual feedback: pulse animation while listening, spinner while thinking, waveform while speaking
- Chat messages show both text AND have a play button for audio replay

## Security
- TTS endpoint requires auth (same as chat)
- ElevenLabs key stays server-side only
- Rate limit TTS calls (prevent abuse)

## Phase 1 (MVP)
- Mic button in web chat
- Web Speech API for STT
- Server-side TTS via ElevenLabs
- Audio playback of responses
- Basic visual states

## Phase 2
- Interrupt support (stop playback when user starts talking)
- iOS native voice support
- Voice activity detection (auto-detect speech start/end)
- Streaming TTS (start playing before full response)
