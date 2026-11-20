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
                string paramsArg = ExtractJsonField(jsonRpcRequest, "arguments");

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

                return "{\"jsonrpc\":\"2.0\",\"id\":" + (id ?? "null") + ",\"result\":{\"isError\":false,\"content\":[{\"type\":\"text\",\"text\":\"Request queued with consent gate ID: " + reqId + "\"}]}}";
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
                default: return toolName;
            }
        }

        private static string ErrorResponse(string id, int code, string message)
        {
            return "{\"jsonrpc\":\"2.0\",\"id\":" + (id ?? "null") + ",\"error\":{\"code\":" + code + ",\"message\":" + Q(message) + "}}";
        }

        private static string ExtractJsonField(string json, string name)
        {
            Match m = Regex.Match(json, "\"" + Regex.Escape(name) + "\"\\s*:\\s*\"?([^\",}]+)\"?");
            return m.Success ? m.Groups[1].Value.Trim() : null;
        }

        private static string Q(string s)
        {
            return "\"" + (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "").Replace("\n", " ") + "\"";
        }
    }
}
