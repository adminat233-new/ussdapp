package com.ussdapp.relay

data class AgentReply(val text: String, val speech: String? = null)

/**
 * The local command set is allowlisted. Natural-language prompts are exposed
 * separately for the explicit AI request path; neither path controls devices.
 */
class MobileAgent(wakeName: String = "Ussd") {
    var wakeName: String = wakeName.trim()
        set(value) { field = value.trim() }

    fun handleText(input: String): AgentReply {
        val command = input.trim()
        if (!command.startsWith("/agent", ignoreCase = true) ||
            (command.length > 6 && !command[6].isWhitespace())) {
            return AgentReply("Use /agent help to see the available commands.")
        }
        return execute(command.substring(6).trim())
    }

    fun aiPromptForText(input: String): String? {
        val command = input.trim()
        if (!command.startsWith("/agent", ignoreCase = true) ||
            (command.length > 6 && !command[6].isWhitespace())) return null
        val prompt = command.substring(6).trim()
        val verb = prompt.substringBefore(' ').lowercase(java.util.Locale.ROOT)
        return if (verb.isEmpty() || verb == "help" || verb == "status" || verb == "say") null else prompt
    }

    fun handleVoice(input: String): AgentReply {
        val name = wakeName
        if (name.isBlank()) return AgentReply("Set a wake name before using voice commands.")
        val spoken = input.trim()
        if (!spoken.startsWith(name, ignoreCase = true) ||
            (spoken.length > name.length && !spoken[name.length].isWhitespace())) {
            return AgentReply("Wake name not detected. No command was run.")
        }

        var command = spoken.substring(name.length).trim()
        if (command.startsWith("/agent", ignoreCase = true) &&
            (command.length == 6 || command[6].isWhitespace())) {
            command = command.substring(6).trim()
        }
        return execute(command)
    }

    fun aiPromptForVoice(input: String): String? {
        val name = wakeName
        val spoken = input.trim()
        if (name.isBlank() || !spoken.startsWith(name, ignoreCase = true) ||
            (spoken.length > name.length && !spoken[name.length].isWhitespace())) return null

        var prompt = spoken.substring(name.length).trim()
        if (prompt.startsWith("/agent", ignoreCase = true) &&
            (prompt.length == 6 || prompt[6].isWhitespace())) {
            prompt = prompt.substring(6).trim()
        }
        val verb = prompt.substringBefore(' ').lowercase(java.util.Locale.ROOT)
        return if (verb.isEmpty() || verb == "help" || verb == "status" || verb == "say") null else prompt
    }

    private fun execute(command: String): AgentReply {
        val separator = command.indexOfFirst { it.isWhitespace() }
        val verb = if (separator < 0) command else command.substring(0, separator)
        val argument = if (separator < 0) "" else command.substring(separator).trim()
        return when (verb.lowercase(java.util.Locale.ROOT)) {
            "", "help" -> AgentReply(
                "Available local commands: /agent help, /agent status, /agent say <text>. " +
                    "Voice: say \"$wakeName help\" or \"$wakeName say <text>\"."
            )
            "status" -> AgentReply(
                "The local assistant is ready. This screen is not connected to a relay. " +
                    "Voice recognition is only started when you tap the voice button."
            )
            "say" -> if (argument.isBlank()) {
                AgentReply("Add text after say. No speech was played.")
            } else if (argument.length > 500) {
                AgentReply("Speech is limited to 500 characters.")
            } else {
                AgentReply(argument, argument)
            }
            else -> AgentReply("Unknown command. Use /agent help. No action was run.")
        }
    }
}
