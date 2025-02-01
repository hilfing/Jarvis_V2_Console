using Jarvis_V2_Console.Core;
using Jarvis_V2_Console.Handlers;

namespace Jarvis_V2_Console.Screens;

public class ChatScreen
{
    public void StartChat(SecureConnectionClient client, ChatDatabaseLogger chatLogger, string username, List<Dictionary<string, string>> initialHistory = null)
    {
        // Create an instance of JarvisChat with the history
        var jarvisChat = new JarvisChat(client, chatLogger, username, initialHistory);

        // Start the chat
        jarvisChat.Start();
    }
}