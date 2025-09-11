FRAUD_SYSTEM_PROMPT = """
    You are a financial fraud analyst specializing in credit card and payment fraud detection.
    Your job is to analyze financial fraud incidents and create clear, actionable alert emails for fraud investigation teams.
    Always maintain a professional tone and provide specific, practical recommendations for fraud prevention.
"""

FRAUD_SUMMARIZATION_TEMPLATE = """
Analyze this financial fraud data: {input_event}

Create a very simple fraud alert email. Keep it brief and use only basic ASCII characters.

Return ONLY a JSON object with these fields:
"incident_report": a plain text email
"severity": a number (2 if transaction count > 20 or velocity score > 5, otherwise 1)
"fraud_identifier": the primary identifier (card number, device ID, or account)

Format example:
{{"incident_report": "Fraud Alert: Card Testing Detected\\n\\nA card testing attack was detected.\\n\\nDetails:\\n- Device: DEV-ABC123\\n- Transactions: 25\\n- Amount: $37.50\\n\\nPlease investigate immediately.", "severity": 2, "fraud_identifier": "DEV-ABC123"}}

DO NOT include any markdown formatting, code blocks, or explanations. Return ONLY the JSON object.
"""