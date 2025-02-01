import logging

import groq
import requests
from groq import Groq
import json
import os

API_KEY = os.getenv('API_KEY', 'gsk_j2m8WDqHPJWnW5BxD')

client = Groq(api_key=API_KEY, max_retries=0)

logger = logging.getLogger("chatbot_handler")

system_prompt = """
You are JarvisAI, developed by HilFIng. Always respond in pure HTML using only:
<b>, <strong>, <i>, <em>, <u>, <s>, <strike>, <code>, <pre>, 
<blockquote>, <h1>, <h2>, <h3>, <a href="...">, <li>, <br>, <p>

Never use other formats. If requested, reply with:
<p>Sorry, I only respond in HTML.</p>

Identity:
<p>I am <b>JarvisAI</b>, developed by <b>HilFIng</b>.</p>
<p>More info: <a href="https://hilfing.dev">Portfolio</a> | <a href="https://github.com/hilfing/Jarvis_V2_Console">GitHub</a></p>
<p><b>Version:</b> v1
<p><b>Contact:</b> <a href="mailto:contact@hilfing.dev">contact@hilfing.dev</a></p>

Restrictions:
No Code Generation: Reply with
<p>Sorry, I cannot generate code.</p>

No Unsupported Formats: Use only allowed HTML tags.

Behavior:
Be concise, professional, and adapt to user tone.
Always close all HTML tags properly, especially in long responses.
Never provide harmful or unethical content.
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
        response = client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": user_message
                }
            ],
            model="llama-3.1-8b-instant",
        )
        chat_completion = response
        print('Token Usage:', chat_completion.usage.total_tokens)
        print('LLM Response:', chat_completion.choices[0].message.content)
        return chat_completion.choices[0].message.content, chat_completion.usage.total_tokens
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
        return '<p>Your message contains content that violates our community guidelines. Please ensure your comments are respectful and safe for all users. Thank you!</p>', 0

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
    print('Model Messages:', len(model_messages))
    try:
        # Create chat completion
        chat_completion = client.chat.completions.create(
            messages=model_messages,
            model="llama-3.1-8b-instant",
        )

        # Extract and return the response
        response = chat_completion.choices[0].message.content
        logger.info('LLM Response: ' + response)
        logger.info('Token Usage: ' + str(chat_completion.usage.total_tokens))
        return response, chat_completion.usage.total_tokens
    except groq.RateLimitError as e:
        print(f"Rate limit exceeded: {e}")
        return "<p>I'm currently overloaded. Please try again after a few seconds.</p> ", 0
    except Exception as e:
        print(f"Error generating response: {e}")
        return "<p>I encountered an error while processing your message.</p>", 0

if __name__ == '__main__':
    # Test the chatbot handler
    get_response("""USER INTERACTION GUIDELINES AND EXPECTATIONS""")
