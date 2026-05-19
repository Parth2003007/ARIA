import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

key = os.getenv("GROQ_API_KEY")
print(f"Key starts: {key[:15] if key else 'NOT FOUND'}")
print(f"Key length: {len(key) if key else 0}")

client = OpenAI(
    api_key=key,
    base_url="https://api.groq.com/openai/v1"
)

try:
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": "say hello"}],
        max_tokens=10
    )
    print("SUCCESS:", response.choices[0].message.content)
except Exception as e:
    print("ERROR:", e)
