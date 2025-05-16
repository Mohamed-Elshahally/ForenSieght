import google.generativeai as genai
import os
import threading

gemini_lock = threading.Lock()

# Existing check_content function (included for reference, assumed from gemini.py)
def check_content2(api_key, message):
    if len(message) == 0:
        return None
    else:
        with gemini_lock:
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel("gemini-1.5-flash")
            # Fix the prompt syntax from the original (remove nested f-string)
            prompt = f'''
You are a senior cybersecurity analyst. Here is a list of observed Windows application Event IDs from the newest to oldest:
{message}

Your task is to analyze these IDs and respond with a single, response with valid JSON object only that contains the following keys:

• is_attack: true if these events form a coherent multi-stage attack, false otherwise  
• threat_level: one of "Low", "Medium", "High", or "Critical"  
• attack_type: a concise label for the likely attack (e.g. "Brute-Force Login", "Privilege Escalation", "Lateral Movement")  
• behaviour: a brief narrative that ties together what these event IDs reveal about the attacker’s behavior  
• evidence_events: an object mapping each Event ID (as a string) to a one-sentence description of what that event signifies
'''
            response = model.generate_content(prompt)
        return response.text