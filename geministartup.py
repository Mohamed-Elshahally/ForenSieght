import google.generativeai as genai
import os
import time
import threading

gemini_lock = threading.Lock()

def check_Startup(api_key, key, name, command: str) -> str:
    if not command or not isinstance(command, str):
        return 'normal'
    prompt = f"Is this Windows startup suspicious? Respond with 'suspicious' or 'normal'. key:{key}, name:{name} Command: {command}"
    try:
        with gemini_lock:
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel('gemini-1.5-flash')
            response = model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    max_output_tokens=50,
                    temperature=0.0
                )
            )
        result = response.text.strip().lower()
        if result == 'suspicious':
            return 'suspicious'
        elif result == 'normal':
            return 'normal'
        else:
            print(f"Unexpected Gemini API response for command '{command}': {result}")
            return 'normal'
    except Exception as e:
        error_msg = str(e).lower()
        print(f"Error calling Gemini API for command '{command}': {str(e)}")
        if 'quota' in error_msg or 'limit' in error_msg or '429' in error_msg:
            print("Quota or rate limit exceeded. Retrying after delay...")
            time.sleep(60)
            return 'normal'
        return 'normal'