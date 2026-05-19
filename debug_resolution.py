import os
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv(dotenv_path="/Users/parth/projects/ARIA/.env")

client = OpenAI(
    api_key=os.getenv("GROQ_API_KEY"),
    base_url="https://api.groq.com/openai/v1"
)

prompt = open("prompts/resolution_prompt.txt").read()

response = client.chat.completions.create(
    model="llama-3.3-70b-versatile",
    messages=[
        {"role": "system", "content": prompt},
        {"role": "user", "content": """
Root cause: Insufficient free disk space on the C drive
Affected system: User's C drive
Diagnosis confidence: 0.95
Category: hardware
Ticket summary: User is receiving low disk space warnings on C drive with only 5 GB left

Select the tool or tools needed to fully resolve this issue.
"""}
    ],
    max_tokens=600,
    temperature=0.1,
)

print("RAW RESPONSE:")
print(response.choices[0].message.content)
