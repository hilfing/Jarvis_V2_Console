using System;
using System.Collections.Generic;
using System.Linq;
using Jarvis_V2_Console.Utils;
using Spectre.Console;
using Spectre.Console.Rendering;
using Markdig;

namespace Jarvis_V2_Console.Screens.ChatScreen;

using System;
using System.Collections.Generic;
using Spectre.Console;

public class JarvisChat
{
    private List<ChatMessage> chatHistory = new List<ChatMessage>();
    private Random random = new Random();

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
            if (userMessage.ToLower() == "exit") break;

            ProcessMessage(userMessage);
        }
    }

    public void ProcessMessage(string userMessage)
    {
        // Add user message to history
        AddMessage("User", userMessage);

        // Generate and display Jarvis response
        string jarvisResponse = GenerateResponse(userMessage);
        AddMessage("Jarvis", jarvisResponse);

        // Render chat history
        RenderChatHistory();
    }

    private void AddMessage(string sender, string content)
    {
        chatHistory.Add(new ChatMessage(sender, content));
    }

    private string GenerateResponse(string userMessage)
    {
        string[] responses = {
            @"
<h2>Client-Side Parsing Setup</h2>
<p>To enable parsing, follow these steps:</p>
<ol>
  <li><strong>Fetch the response data:</strong> Use an HTTP request to fetch the data from our API.</li>
  <li><strong>Handle JSON response:</strong> Check the response Content-Type header for <code>application/json</code> to handle JSON data.</li>
  <li><strong>Iterate through the response:</strong> Loop through the response data to access and parse individual elements.</li>
</ol>
<p>Example using JavaScript:</p>
<code>
fetch('https://your-api-endpoint.com/data')
  .then(response => response.json())
  .then(data => {
    <b>loop through</b> the data array
    data.forEach(item => {
      console.log(item.id, item.name);
    });
  })
  .catch(error => console.error('Error:', error));
</code>
<p>Note: This is a basic example, you should adapt it to your specific requirements.</p>
"
        };

        return responses[random.Next(responses.Length)];
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
            Color senderColor = message.Sender == "User" ? Color.Gold1 : Color.Magenta1;
            var formattedContent = GeneralUtils.ConvertHtmlToMarkup(message.Content);
            
            table.AddRow(
                new Markup(message.Timestamp.ToString("HH:mm:ss")),
                new Markup($"[{senderColor.ToMarkup()}]{message.Sender}[/]"),
                new Markup(formattedContent)
            );
        }

        return table;
    }
}