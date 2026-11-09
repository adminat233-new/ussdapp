import AVFoundation
import Combine
import Foundation
import Speech

@MainActor
final class MobileAgent: NSObject, ObservableObject {
    @Published var response = "Ready. Try /agent help."
    @Published var isListening = false
    @Published var apiKeySaved = false
    @Published var wakeName: String {
        didSet { wakeName = wakeName.trimmingCharacters(in: .whitespacesAndNewlines) }
    }

    private let synthesizer = AVSpeechSynthesizer()
    private let ai = GeminiAssistant()
    private let audioEngine = AVAudioEngine()
    private var recognizer: SFSpeechRecognizer?
    private var recognitionRequest: SFSpeechAudioBufferRecognitionRequest?
    private var recognitionTask: SFSpeechRecognitionTask?
    private var inputTapInstalled = false

    override init() {
        wakeName = UserDefaults.standard.string(forKey: "assistant.wakeName") ?? "Ussd"
        super.init()
        recognizer = SFSpeechRecognizer(locale: Locale.current)
        apiKeySaved = ai.hasAPIKey()
    }

    func runTextCommand(_ input: String) {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.range(of: "^/agent(?:\\s|$)", options: [.regularExpression, .caseInsensitive]) != nil else {
            response = "Use /agent help to see the available commands."
            return
        }
        let command = String(trimmed.dropFirst(6)).trimmingCharacters(in: .whitespacesAndNewlines)
        if let prompt = aiPrompt(command) {
            askAI(prompt)
        } else if runCommand(command) {
            speak(response)
        }
    }

    func saveAPIKey(_ key: String) {
        do {
            try ai.saveAPIKey(key)
            apiKeySaved = true
            response = "API key securely saved on this device."
        } catch {
            response = "Could not save API key: \(error.localizedDescription)"
        }
    }

    func removeAPIKey() {
        do {
            try ai.removeAPIKey()
            apiKeySaved = false
            response = "Saved API key removed."
        } catch {
            response = "Could not remove API key: \(error.localizedDescription)"
        }
    }

    func askAI(_ prompt: String, speakResponse: Bool = false) {
        guard apiKeySaved else {
            response = "Add a Gemini API key first. No shared or bundled API key is provided."
            return
        }
        response = "Contacting \(GeminiAssistant.defaultModel)…"
        ai.ask(prompt) { [weak self] result in
            DispatchQueue.main.async {
                guard let self = self else { return }
                switch result {
                case .success(let answer):
                    self.response = answer
                    if speakResponse { self.speak(answer) }
                case .failure(let error):
                    self.response = "AI request failed: \(error.localizedDescription)"
                }
            }
        }
    }

    func speak(_ text: String) {
        guard !text.isEmpty else { return }
        synthesizer.stopSpeaking(at: .immediate)
        synthesizer.speak(AVSpeechUtterance(string: text))
    }

    func startListening() {
        guard !wakeName.isEmpty else {
            response = "Set a wake name before using voice commands."
            return
        }
        guard let recognizer = recognizer, recognizer.isAvailable,
              recognizer.supportsOnDeviceRecognition else {
            response = "On-device speech recognition is unavailable for the current language."
            return
        }

        SFSpeechRecognizer.requestAuthorization { [weak self] status in
            DispatchQueue.main.async {
                guard let self = self else { return }
                guard status == .authorized else {
                    self.response = "Speech recognition permission was denied."
                    return
                }
                AVAudioSession.sharedInstance().requestRecordPermission { granted in
                    DispatchQueue.main.async {
                        guard granted else {
                            self.response = "Microphone permission was denied. Voice input was not started."
                            return
                        }
                        self.beginOnDeviceRecognition(recognizer)
                    }
                }
            }
        }
    }

    func stopListening() {
        if audioEngine.isRunning {
            audioEngine.stop()
        }
        if inputTapInstalled {
            audioEngine.inputNode.removeTap(onBus: 0)
            inputTapInstalled = false
        }
        recognitionRequest?.endAudio()
        isListening = false
        deactivateAudioSession()
    }

    private func deactivateAudioSession() {
        do {
            try AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
        } catch {
            response = "Could not release the microphone audio session: \(error.localizedDescription)"
        }
    }

    private func beginOnDeviceRecognition(_ recognizer: SFSpeechRecognizer) {
        cancelRecognition()
        do {
            let session = AVAudioSession.sharedInstance()
            try session.setCategory(.record, mode: .measurement, options: .duckOthers)
            try session.setActive(true, options: .notifyOthersOnDeactivation)

            let request = SFSpeechAudioBufferRecognitionRequest()
            request.shouldReportPartialResults = false
            request.requiresOnDeviceRecognition = true
            recognitionRequest = request

            let input = audioEngine.inputNode
            input.installTap(onBus: 0, bufferSize: 1024, format: input.outputFormat(forBus: 0)) {
                [weak request] buffer, _ in
                request?.append(buffer)
            }
            inputTapInstalled = true
            audioEngine.prepare()
            try audioEngine.start()
            isListening = true
            response = "Listening once for the wake name and a command…"
            recognitionTask = recognizer.recognitionTask(with: request) { [weak self] result, error in
                guard let self = self else { return }
                if let result = result, result.isFinal {
                    DispatchQueue.main.async {
                        self.recognitionTask = nil
                        self.stopListening()
                        self.recognitionRequest = nil
                        self.runVoiceCommand(result.bestTranscription.formattedString)
                    }
                } else if let error = error {
                    DispatchQueue.main.async {
                        self.recognitionTask = nil
                        self.stopListening()
                        self.recognitionRequest = nil
                        self.response = "Speech recognition failed: \(error.localizedDescription)"
                    }
                }
            }
        } catch {
            cancelRecognition()
            response = "Could not start speech recognition: \(error.localizedDescription)"
        }
    }

    private func cancelRecognition() {
        if audioEngine.isRunning {
            audioEngine.stop()
        }
        if inputTapInstalled {
            audioEngine.inputNode.removeTap(onBus: 0)
            inputTapInstalled = false
        }
        recognitionRequest?.endAudio()
        recognitionTask?.cancel()
        recognitionTask = nil
        recognitionRequest = nil
        isListening = false
        deactivateAudioSession()
    }

    private func runVoiceCommand(_ input: String) {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        let name = wakeName
        guard trimmed.lowercased().hasPrefix(name.lowercased()),
              trimmed.count == name.count || trimmed.dropFirst(name.count).first?.isWhitespace == true else {
            response = "Wake name not detected. No command was run."
            return
        }
        var command = String(trimmed.dropFirst(name.count)).trimmingCharacters(in: .whitespacesAndNewlines)
        if command.range(of: "^/agent(?:\\s|$)", options: [.regularExpression, .caseInsensitive]) != nil {
            command = String(command.dropFirst(6)).trimmingCharacters(in: .whitespacesAndNewlines)
        }
        if let prompt = aiPrompt(command) {
            askAI(prompt, speakResponse: true)
            return
        }
        runCommand(command)
        speak(response)
    }

    private func aiPrompt(_ command: String) -> String? {
        let verb = command.split(whereSeparator: { $0.isWhitespace }).first.map(String.init)?.lowercased() ?? ""
        return ["", "help", "status", "say"].contains(verb) ? nil : command
    }

    @discardableResult
    private func runCommand(_ command: String) -> Bool {
        let pieces = command.split(maxSplits: 1, whereSeparator: { $0.isWhitespace })
        let verb = pieces.first.map(String.init)?.lowercased() ?? ""
        let argument = pieces.count > 1 ? String(pieces[1]).trimmingCharacters(in: .whitespacesAndNewlines) : ""
        switch verb {
        case "", "help":
            response = "Available local commands: /agent help, /agent status, /agent say <text>. " +
                "Voice: say \"\(wakeName) help\" or \"\(wakeName) say <text>\"."
            return true
        case "status":
            response = "The local assistant is ready. This screen is not connected to a relay. " +
                "Voice recognition is only started when you tap Listen."
            return true
        case "say":
            guard !argument.isEmpty else {
                response = "Add text after say. No speech was played."
                return true
            }
            guard argument.count <= 500 else {
                response = "Speech is limited to 500 characters."
                return true
            }
            response = argument
            return true
        default:
            response = "Unknown command. Use /agent help. No action was run."
            return false
        }
    }
}
