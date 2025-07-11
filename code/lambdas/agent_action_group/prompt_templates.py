SYSTEM_PROMPT = """
    You are a data analyst that reviews network events.
    Analyze the provided data and create a summary report.
"""


SUMMARIZATION_TEMPLATE_PARAGRAPH = """
Analyze this network data and provide a JSON response with these fields:

"incident_report": "Summary of the network event with all details"
"severity": "2" (if fragment count > 20, otherwise "1")
"ip_address": "source IP from the data"

Data to analyze: {input_event}

Return only valid JSON:
"""
