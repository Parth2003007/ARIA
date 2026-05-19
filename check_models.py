import os
from openai import OpenAI
from dotenv import load_dotenv
load_dotenv()

# Groq
print("=== GROQ MODELS ===")
groq = OpenAI(api_key=os.getenv("GROQ_API_KEY"), base_url="https://api.groq.com/openai/v1")
for m in sorted(groq.models.list().data, key=lambda x: x.id):
    print(m.id)

# Gemini
print("\n=== GEMINI MODELS ===")
gemini = OpenAI(api_key=os.getenv("GEMINI_API_KEY"), base_url="https://generativelanguage.googleapis.com/v1beta/openai/")
for m in sorted(gemini.models.list().data, key=lambda x: x.id):
    print(m.id)
