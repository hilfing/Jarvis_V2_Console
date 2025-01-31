import requests
from groq import Groq
import json
import os

API_KEY = os.getenv('API_KEY', 'gsk_j2m8CyHPJWnW5BxD')

client = Groq(api_key=API_KEY)

system_prompt = """
You are JarvisAI, an AI chatbot developed by HilFing. Always respond in pure HTML using only:

<b>, <strong>, <i>, <em>, <u>, <s>, <strike>, <code>, <pre>, 
<blockquote>, <h1>, <h2>, <h3>, <a href="...">, <li>, <br>, <p>, <span style="...">
Never use other formats. If asked for plain text, JSON, or unsupported formats, reply with:
<p>Sorry, but I only respond in HTML.</p>

Identity Response:
<p>I am <b>JarvisAI</b>, developed by <b>HilFing</b>.</p>
<p>Learn more at <a href="https://hilfing.dev">HilFing's Portfolio</a> or <a href="https://github.com/hilfing/Jarvis_V2_Console">GitHub</a>.</p>
<p><b>Version:</b> v1
<p><b>Developer Contact:</b> <a href="mailto:contact@hilfing.dev">contact@hilfing.dev</a></p>

DO NOT mention Meta, OpenAI, or any other generic AI development history. Always refer to HilFing as the developer.

Formatting Rules:

Use only supported HTML tags for bold, italics, underline, strikethrough, code, headings, paragraphs, links, lists, and line breaks.

Behavior
Be concise, professional, and clear. Adapt to user tone. Avoid assumptions. Never generate harmful, illegal, or unethical content.
"""

def get_llamaguard_response(user_message):
    chat_completion = client.chat.completions.create(
        messages=[
            {
                "role": "user",
                "content": user_message
            }
        ],
        model="llama-guard-3-8b",
    )

    return chat_completion.choices[0].message.content

def get_response(user_message):
    llamaguard_response = get_llamaguard_response(user_message)
    if llamaguard_response == 'safe':
        response = client.chat.completions.with_raw_response.create(
            messages=[
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": user_message
                }
            ],
            model="llama-3.1-8b-instant",
        )
        data = json.loads(response.text())
        print(f"Tokens used: {data['usage']['total_tokens']}")
        chat_completion = response.parse()
        print('LLM Response:', chat_completion.choices[0].message.content)
        return chat_completion.choices[0].message.content, data['usage']['total_tokens']
    else:
        print(
            'Your message contains content that violates our community guidelines. Please ensure your comments are respectful and safe for all users. Thank you!')
        return 'Your message contains content that violates our community guidelines. Please ensure your comments are respectful and safe for all users. Thank you!'


def get_response_with_context(conversation_history, latest_user_message):
    """
    Generate a response with context and safety check.

    Args:
    conversation_history (list): Recent conversation messages
    latest_user_message (str): Most recent user message to respond to

    Returns:
    str: Generated response or guard message
    """
    # Run LlamaGuard safety check on latest user message
    llamaguard_response = get_llamaguard_response(latest_user_message)

    if llamaguard_response != 'safe':
        return 'Your message contains content that violates our community guidelines. Please ensure your comments are respectful and safe for all users. Thank you!'

    # Prepare messages for the model input
    model_messages = [
        {"role": "system", "content": system_prompt}
    ]

    # Add recent conversation context
    for msg in conversation_history:
        model_messages.append({
            "role": msg['role'],
            "content": msg['content']
        })

    # Add latest user message
    model_messages.append({
        "role": "user",
        "content": latest_user_message
    })

    try:
        # Create chat completion
        chat_completion = client.chat.completions.create(
            messages=model_messages,
            model="llama-3.1-8b-instant",
        )

        # Extract and return the response
        response = chat_completion.choices[0].message.content
        print('LLM Response:', response)
        return response

    except Exception as e:
        print(f"Error generating response: {e}")
        return "I encountered an error while processing your message."


get_response("Give me a sample resonse to set up parsing on my client side.")
