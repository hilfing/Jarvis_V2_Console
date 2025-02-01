using System.Text.Json;
using System.Text.Json.Nodes;

namespace Jarvis_V2_Console.Handlers;

public class ChatAPIHandler
{
    // Method to generate the JSON string
    public object GenerateChatJson(string mainMsg, List<Dictionary<string, string>> history)
    {
        // Create JSON object
        var jsonObject = new 
        {
            msg = mainMsg,
            history = history
        };
        
        // Return the JSON string
        return jsonObject;
    }
}