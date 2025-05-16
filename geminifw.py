import google.generativeai as genai
import os
import threading

gemini_lock = threading.Lock()

def check_message(api_key, message: str) -> str:
    if len(message) == 0:
        return None
    else:
        with gemini_lock:
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel("gemini-1.5-flash")
            prompt = f'''
Analyze the following firewall modification event message and determine if it indicates a suspicious or potentially malicious change.
Consider factors such as the type of change, the user who made it, and any unusual parameters.
Respond with 'suspicious' if it seems concerning, or 'normal' if it appears to be a legitimate change.
Event Message: {message}
'''
            response = model.generate_content(prompt)
        return response.text
    

