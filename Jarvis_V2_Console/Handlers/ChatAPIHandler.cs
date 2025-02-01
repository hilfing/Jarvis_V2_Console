using System.Text.Json;
using System.Text.Json.Nodes;
using Jarvis_V2_Console.Models;

namespace Jarvis_V2_Console.Handlers;

public class ChatAPIHandler
{
    // Method to generate the JSON string
    public object GenerateChatJson(string mainMsg, List<Dictionary<string, string>> history)
    {
        // Create JSON object
        var jsonObject = new ChatData
        {
            Msg = mainMsg,
            History = history
        };
        
        // Return the JSON string
        return jsonObject;
    }
}