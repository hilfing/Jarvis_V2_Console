using System;
using System.Collections.Generic;
using System.Linq;
using Jarvis_V2_Console.Core;
using Jarvis_V2_Console.Utils;
using Newtonsoft.Json;
using Spectre.Console;
using Spectre.Console.Rendering;

namespace Jarvis_V2_Console.Handlers;

public class JarvisChat
{
    private static Logger logger = new Logger("JarvisAI.Handlers.JarvisChat");
    private List<ChatMessage> chatHistory = new List<ChatMessage>();
    private static SecureConnectionClient client;
    private ChatDatabaseLogger chatLogger;
    private string username;

    public JarvisChat(SecureConnectionClient _client, ChatDatabaseLogger _chatLogger, string _username, List<Dictionary<string, string>> initialHistory = null)
    {
        client = _client;
        chatLogger = _chatLogger;
        username = _username;
        if (initialHistory != null)
        {
            // Add the last two conversation sets to the chat history
            foreach (var historyItem in initialHistory.TakeLast(2))
            {
                chatHistory.Add(new ChatMessage(historyItem["role"], historyItem["content"]));
                Console.WriteLine(historyItem["role"]);
            }
        }
        logger.Info("JarvisChat initialized");
    }

    public class ChatMessage
    {
        public string Sender { get; set; }
        public string Content { get; set; }
        public DateTime Timestamp { get; set; }

        public ChatMessage(string sender, string content)
        {
            Sender = sender;
            Content = content;
            Timestamp = DateTime.Now;
        }
    }

    public void Start()
    {
        AnsiConsole.Write(
            new FigletText("Jarvis Chat")
                .Color(Color.Blue)
        );

        while (true)
        {
            string userMessage = AnsiConsole.Prompt(
                new TextPrompt<string>("[cyan]User>[/]")
                    .PromptStyle("green")
            );

            if (string.IsNullOrWhiteSpace(userMessage)) continue;
            if (userMessage.ToLower() == "/exit")
            {
                AnsiConsole.MarkupLine("[red]Exiting Jarvis Chat...[/]");
                logger.Info("Exiting Jarvis Chat...");
                break;
            }

            ProcessMessage(userMessage);
        }
    }

    public void ProcessMessage(string userMessage)
    {
        if (string.IsNullOrWhiteSpace(userMessage)) return;
        AddMessage("User", userMessage);

        if (userMessage[0] == "/command"[0])
        {
            logger.Info($"Command detected. Processing command: {userMessage}");
            // Handle commands
            string command = userMessage.Substring(1);
            switch (command)
            {
                case "help":
                    string response = """
                        [yellow][bold]Commands:[/][/]
                        [yellow]/clear[/]: Clear chat history
                        """; 
                    AddMessage("Assistant", response);
                    break;
                case "clear":
                    AddMessage("Assistant", "[red]Chat history cleared.[/]");
                    chatHistory.Clear();
                    break;
                default:
                    AddMessage("Assistant", "[red]Invalid command. Please try again. Use /help for a list of commands.[/]");
                    break;
            }
        }
        else
        {
            // Generate and display Jarvis response
            string jarvisResponse = GenerateResponse(userMessage);
            AddMessage("Assistant", jarvisResponse);
        }
        // Render chat history
        RenderChatHistory();
    }

    private void AddMessage(string sender, string content)
    {
        if (string.IsNullOrWhiteSpace(content)) return;
        if (sender.ToLower() == "user")
        {
            logger.Info($"{username}: {content}");
            chatLogger.LogMessage(username, content, true).GetAwaiter().GetResult();
            chatHistory.Add(new ChatMessage("user", content));
        }
        else
        {
            logger.Info($"Jarvis: {content}");
            chatLogger.LogMessage("Jarvis", content, false).GetAwaiter().GetResult();
            chatHistory.Add(new ChatMessage("assistant", content));
        }
    }

    private string GenerateResponse(string userMessage)
    {
        // Create a list to hold the last two conversation sets
        var history = new List<Dictionary<string, string>>();

        // Add the last two conversation sets to the history
        foreach (var message in chatHistory.TakeLast(2))
        {
            history.Add(new Dictionary<string, string>
            {
                { "role", message.Sender.ToLower() }, // Ensure role is in lowercase
                { "content", message.Content }
            });
        }

        // Create an instance of ChatAPIHandler
        ChatAPIHandler chatHandler = new ChatAPIHandler();

        // Generate the JSON string using the chat processor
        var jsonString = chatHandler.GenerateChatJson(userMessage, history);

        // Send the request and get the response (assuming client is initialized elsewhere)
        var response = client.SendEncryptedChatRequestAsync("chat", jsonString).GetAwaiter().GetResult();

        // Extract the response content (assuming the response is in JSON format)
        if (!response.IsSuccess)
        {
            return "Sorry, I am currently offline. Please try again later.";
        }
        var responseData = JsonConvert.DeserializeObject<Dictionary<string, object>>(response.Data);
        string responseContent = responseData["response"].ToString();

        // Return the response content
        return responseContent;
    }

    private void RenderChatHistory()
    {
        AnsiConsole.Clear();

        // Redraw title
        AnsiConsole.Write(
            new FigletText("Jarvis Chat")
                .Color(Color.Blue)
        );

        // Create chat panel
        var panel = new Panel(CreateChatTable())
            .Header("Chat History", Justify.Center)
            .Border(BoxBorder.Rounded)
            .BorderColor(Color.Aquamarine1);

        AnsiConsole.Write(panel);
    }

    private Table CreateChatTable()
    {
        var table = new Table()
            .BorderColor(Color.Grey)
            .AsciiBorder()
            .Centered();

        table.AddColumn("[blue]Timestamp[/]");
        table.AddColumn("[blue]Sender[/]");
        table.AddColumn("[blue]Message[/]");

        foreach (var message in chatHistory)
        {
            Color senderColor = message.Sender == "user" ? Color.Gold1 : Color.Magenta1;

            // Convert HTML content to Spectre.Console markup
            var formattedContent = GeneralUtils.ConvertHtmlToMarkup(message.Content);
            string sender;
            if (message.Sender == "user")
            {
                sender = username;
            }
            else
            {
                sender = "Jarvis";
            }


            table.AddRow(
                new Markup(message.Timestamp.ToString("HH:mm:ss")),
                new Markup($"[{senderColor.ToMarkup()}]{sender}[/]"),
                new Markup(formattedContent));
        };
        return table;
    }
}
