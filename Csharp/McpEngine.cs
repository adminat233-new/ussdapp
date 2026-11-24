using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace UssdApp
{
    // =========================================================================
    // Model Context Protocol (MCP) & Autonomous Tool Dispatcher
    //
    // Implements JSON-RPC 2.0 based MCP tool discovery and execution for the
    // autonomous AI assistant. Tools are self-describing, parameter-validated,
    // and gated through the RemoteControl permission/audit subsystem.
    // =========================================================================

    public sealed class McpToolDefinition
    {
        public string Name;
        public string Description;
        public string InputSchemaJson;
        public bool IsDangerous;
    }

    public sealed class McpToolCallResult
    {
        public bool Success;
        public string Content = "";
        public string Error = "";
        public bool IsError;
    }

    public static class McpEngine
    {
        private static readonly Dictionary<string, McpToolDefinition> _tools = new Dictionary<string, McpToolDefinition>(StringComparer.OrdinalIgnoreCase);

        static McpEngine()
        {
            RegisterTool("get_system_telemetry", "Retrieve CPU, memory, uptime, and system diagnostics", "{}", false);
            RegisterTool("query_device_location", "Determine GPS/Network coordinates using Windows Location API & IP fallback", "{}", true);
            RegisterTool("trigger_security_alarm", "Emit audible alert chime pulses to pinpoint a lost or stolen device", "{\"rings\":\"number\"}", true);
            RegisterTool("lock_workstation", "Engage local Windows workstation lock screen via native OS API", "{}", true);
            RegisterTool("capture_viewport", "Take a snapshot screenshot of the current active primary display", "{}", true);
            RegisterTool("send_cellular_sms", "Dispatch a GSM SMS message to a destination phone number via connected modem", "{\"recipient\":\"string\",\"message\":\"string\"}", true);
            RegisterTool("execute_carrier_ussd", "Execute a USSD string code (e.g. *124#) via MiFi HTTP API or serial AT commands", "{\"code\":\"string\"}", false);
            RegisterTool("list_directory_files", "Inspect directory contents within safe user profile or documents scope", "{\"path\":\"string\"}", false);
            RegisterTool("read_text_file", "Read text content of a bounded document file up to 512 KB", "{\"path\":\"string\"}", true);
            RegisterTool("report_connectivity_mesh", "Evaluate NAT, DERP relay, STUN status and candidate route matrix", "{}", false);
            RegisterTool("open_laptop_tracker", "Open the installed FIND laptop tracker desktop app after local approval", "{}", true);
            RegisterTool("open_calls_companion", "Open the installed USSD Manager cross-platform voice, video and text companion", "{}", true);
            RegisterTool("initiate_call", "Start a voice or video call to a 700-series app number over the relay", "{\"number\":\"string\",\"video\":\"boolean\"}", true);
            RegisterTool("answer_call", "Answer the current incoming call after local approval", "{}", true);
            RegisterTool("reject_call", "Reject the current incoming call after local approval", "{}", true);
            RegisterTool("end_call", "End the current active call after local approval", "{}", true);
            RegisterTool("send_chat", "Send a sealed text chat message to a 700-series app number", "{\"number\":\"string\",\"message\":\"string\"}", true);
        }

        public static void RegisterTool(string name, string description, string inputSchema, bool isDangerous)
        {
            _tools[name] = new McpToolDefinition
            {
                Name = name,
                Description = description,
                InputSchemaJson = inputSchema,
                IsDangerous = isDangerous
            };
        }

        public static IEnumerable<McpToolDefinition> ListTools()
        {
            return _tools.Values;
        }

        public static string GetToolsManifestJson()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("{\"tools\":[");
            bool first = true;
            foreach (var t in _tools.Values)
            {
                if (!first) sb.Append(",");
                first = false;
                sb.Append("{");
                sb.Append("\"name\":").Append(Q(t.Name)).Append(",");
                sb.Append("\"description\":").Append(Q(t.Description)).Append(",");
                sb.Append("\"inputSchema\":").Append(t.InputSchemaJson).Append(",");
                sb.Append("\"isDangerous\":").Append(t.IsDangerous ? "true" : "false");
                sb.Append("}");
            }
            sb.Append("]}");
            return sb.ToString();
        }

        // Handles standard MCP JSON-RPC 2.0 messages: tools/list and tools/call
        public static string ProcessMcpJsonRpc(string jsonRpcRequest, RemoteControl rc, string callerIdentity)
        {
            if (string.IsNullOrEmpty(jsonRpcRequest))
                return ErrorResponse(null, -32700, "Parse error");

            string id = ExtractJsonField(jsonRpcRequest, "id");
            string method = ExtractJsonField(jsonRpcRequest, "method");

            if (string.Equals(method, "tools/list", StringComparison.OrdinalIgnoreCase))
            {
                return "{\"jsonrpc\":\"2.0\",\"id\":" + (id ?? "null") + ",\"result\":" + GetToolsManifestJson() + "}";
            }
            else if (string.Equals(method, "tools/call", StringComparison.OrdinalIgnoreCase))
            {
                string toolName = ExtractJsonField(jsonRpcRequest, "name");
                string rawArgs = ExtractJsonField(jsonRpcRequest, "arguments");
                string paramsArg = NormalizeMcpArguments(toolName, rawArgs);

                if (string.IsNullOrEmpty(toolName) || !_tools.ContainsKey(toolName))
                    return ErrorResponse(id, -32601, "Method/Tool not found: " + toolName);

                McpToolDefinition def = _tools[toolName];

                // Map MCP tool to RemoteControl command
                string rcCommand = MapMcpToRemoteControlCommand(toolName);
                string reqId = rc.Request(callerIdentity ?? "mcp_client", rcCommand, paramsArg);

                if (string.IsNullOrEmpty(reqId))
                {
                    return "{\"jsonrpc\":\"2.0\",\"id\":" + (id ?? "null") + ",\"result\":{\"isError\":true,\"content\":[{\"type\":\"text\",\"text\":\"Tool execution rejected or rate-limited.\"}]}}";
                }

                return "{\"jsonrpc\":\"2.0\",\"id\":" + (id ?? "null") + ",\"result\":{\"isError\":false,\"content\":[{\"type\":\"text\",\"text\":\"Queued for consent approval (not yet executed). Consent gate ID: " + reqId + "\"}]}}";
            }

            return ErrorResponse(id, -32601, "Unsupported method: " + method);
        }

        private static string MapMcpToRemoteControlCommand(string toolName)
        {
            switch (toolName.ToLowerInvariant())
            {
                case "get_system_telemetry": return "sysinfo";
                case "query_device_location": return "locatedevice";
                case "trigger_security_alarm": return "ringdevice";
                case "lock_workstation": return "lockscreen";
                case "capture_viewport": return "screenshot";
                case "send_cellular_sms": return "sendsms";
                case "execute_carrier_ussd": return "runussd";
                case "list_directory_files": return "listfiles";
                case "read_text_file": return "readfile";
                case "report_connectivity_mesh": return "derp_status";
                case "open_laptop_tracker": return "opentracker";
                case "open_calls_companion": return "opencalls";
                case "initiate_call": return "startcall";
                case "answer_call": return "answercall";
                case "reject_call": return "rejectcall";
                case "end_call": return "endcall";
                case "send_chat": return "sendchat";
                default: return toolName;
            }
        }

        private static string ErrorResponse(string id, int code, string message)
        {
            return "{\"jsonrpc\":\"2.0\",\"id\":" + (id ?? "null") + ",\"error\":{\"code\":" + code + ",\"message\":" + Q(message) + "}}";
        }

        // The relay's RemoteControl commands use simple pipe-delimited arguments.
        // Convert the MCP JSON object once, centrally, instead of teaching every
        // command to parse JSON (and instead of trusting the old flat regex).
        private static string NormalizeMcpArguments(string toolName, string raw)
        {
            string rawArgs = raw ?? "";
            switch ((toolName ?? "").ToLowerInvariant())
            {
                case "send_cellular_sms":
                    return PipeArg(ExtractJsonField(rawArgs, "recipient"), ExtractJsonField(rawArgs, "message"));
                case "send_chat":
                    return PipeArg(ExtractJsonField(rawArgs, "number"), ExtractJsonField(rawArgs, "message"));
                case "initiate_call":
                    string number = ExtractJsonField(rawArgs, "number") ?? "";
                    string video = ExtractJsonField(rawArgs, "video") ?? "";
                    if (number.Length == 0) return rawArgs;
                    return number + "|" + (string.Equals(video, "true", StringComparison.OrdinalIgnoreCase) ? "video" : "voice");
                default:
                    return rawArgs;
            }
        }

        private static string PipeArg(string first, string second)
        {
            if (string.IsNullOrEmpty(first) || string.IsNullOrEmpty(second)) return "";
            return first + "|" + second;
        }

        // Small scanner for the flat fields MCP uses here. Unlike the previous
        // regex it survives nested "arguments" objects and escaped quotes.
        private static string ExtractJsonField(string json, string name)
        {
            if (string.IsNullOrEmpty(json) || string.IsNullOrEmpty(name)) return null;
            string key = "\"" + name + "\"";
            int pos = json.IndexOf(key, StringComparison.OrdinalIgnoreCase);
            if (pos < 0) return null;
            int i = pos + key.Length;
            SkipJsonWhitespace(json, ref i);
            if (i >= json.Length || json[i] != ':') return null;
            i++;
            SkipJsonWhitespace(json, ref i);
            if (i >= json.Length) return null;
            if (json[i] == '"') return ParseJsonString(json, ref i);
            if (json[i] == '{')
            {
                int end = FindMatchingBrace(json, i);
                if (end < 0) return null;
                int start = i + 1;
                return json.Substring(start, end - start);
            }
            int tokenStart = i;
            while (i < json.Length && json[i] != ',' && json[i] != '}' &&
                   json[i] != ']' && !char.IsWhiteSpace(json[i])) i++;
            if (i == tokenStart) return null;
            return json.Substring(tokenStart, i - tokenStart);
        }

        private static void SkipJsonWhitespace(string json, ref int i)
        {
            while (i < json.Length && char.IsWhiteSpace(json[i])) i++;
        }

        private static int FindMatchingBrace(string json, int start)
        {
            int depth = 0;
            bool inString = false;
            bool escaped = false;
            for (int i = start; i < json.Length; i++)
            {
                char c = json[i];
                if (inString)
                {
                    if (escaped) escaped = false;
                    else if (c == '\\') escaped = true;
                    else if (c == '"') inString = false;
                    continue;
                }
                if (c == '"') inString = true;
                else if (c == '{') depth++;
                else if (c == '}')
                {
                    depth--;
                    if (depth == 0) return i;
                }
            }
            return -1;
        }

        private static string ParseJsonString(string json, ref int i)
        {
            StringBuilder sb = new StringBuilder();
            i++; // opening quote
            while (i < json.Length)
            {
                char c = json[i++];
                if (c == '"') break;
                if (c != '\\') { sb.Append(c); continue; }
                if (i >= json.Length) break;
                char e = json[i++];
                if (e == 'u' && i + 4 <= json.Length)
                {
                    string hex = json.Substring(i, 4);
                    int code;
                    if (int.TryParse(hex, System.Globalization.NumberStyles.HexNumber,
                            System.Globalization.CultureInfo.InvariantCulture, out code))
                    {
                        sb.Append((char)code);
                        i += 4;
                        continue;
                    }
                }
                if (e == 'n') sb.Append('\n');
                else if (e == 'r') sb.Append('\r');
                else if (e == 't') sb.Append('\t');
                else sb.Append(e);
            }
            return sb.ToString();
        }

        private static string Q(string s)
        {
            return "\"" + (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "").Replace("\n", " ") + "\"";
        }
    }
}
