import json
import boto3
import os
from fraud_prompt_templates import FRAUD_SYSTEM_PROMPT, FRAUD_SUMMARIZATION_TEMPLATE

TOPIC_ARN = os.environ.get("TOPIC_ARN", "")
REGION_NAME = os.environ.get("REGION_NAME", "us-west-2")

sns_client = boto3.client("sns", region_name=REGION_NAME)
bedrock_runtime = boto3.client("bedrock-runtime", region_name=REGION_NAME)

def lambda_handler(event, context):
    try:
        print(f"Received event: {json.dumps(event)}")
        
        agent = event.get('agent', 'unknown')
        actionGroup = event.get('actionGroup', 'unknown')
        function = event.get('function', 'unknown')
        parameters = event.get('parameters', [])
        
        params = {p['name']: p['value'] for p in parameters}
        print(f"Function: {function}, Params: {params}")
        
        if function == 'generateTemplate':
            print(f"Processing generateTemplate function")
            event_data = params.get('eventData', 'No event data provided')
            print(f"Event data received: {event_data[:100]}...")
            
            # Sanitize input data for financial fraud context
            sanitized_data = event_data.replace('Card Testing Fraud Detection', 'Transaction Pattern Analysis')
            sanitized_data = sanitized_data.replace('Velocity Fraud Detection', 'Geographic Transaction Analysis')
            sanitized_data = sanitized_data.replace('Fraudulent Card', 'Suspicious Card')
            sanitized_data = sanitized_data.replace('Suspicious Device', 'Flagged Device')
            sanitized_data = sanitized_data.replace('Attack', 'Incident')
            
            prompt = f"{FRAUD_SYSTEM_PROMPT}\n\n{FRAUD_SUMMARIZATION_TEMPLATE.format(input_event=sanitized_data)}"
            print(f"Sanitized data sent to Nova: {sanitized_data}")

            request_body = {
                "schemaVersion": "messages-v1",
                "messages": [
                    {
                        "role": "user", 
                        "content": [{"text": prompt}]
                    }
                ],
                "inferenceConfig": {
                    "maxTokens": 512,
                    "temperature": 0
                }
            }
            
            try:
                response = bedrock_runtime.invoke_model(
                    modelId="us.amazon.nova-micro-v1:0",
                    body=json.dumps(request_body)
                )

                result = json.loads(response['body'].read())
                content = result['output']['message']['content'][0]['text'].strip()
                print(f"Raw Nova response: '{content}'")

                # Clean up the response to ensure valid JSON
                if content.startswith('```'):
                    content = content.split('```')[1].strip()
                    if content.startswith('json'):
                        content = content[4:].strip()
                
                # Remove any leading/trailing non-JSON characters
                content = content.strip()
                if not content.startswith('{'):
                    content = content[content.find('{'):]
                if not content.endswith('}'): 
                    content = content[:content.rfind('}')+1]
                
                # Remove leading/trailing whitespace and newlines from JSON structure
                import re
                content = re.sub(r'\n(?=\s*[{}\[\],:])', '', content)
                content = re.sub(r'\n(?=\s*$)', '', content)
                
                # Replace newlines inside JSON string values with escaped newlines
                def escape_newlines_in_strings(text):
                    result = []
                    in_string = False
                    i = 0
                    while i < len(text):
                        char = text[i]
                        if char == '"' and (i == 0 or text[i-1] != '\\'):
                            in_string = not in_string
                        elif char == '\n' and in_string:
                            result.append('\\n')
                            i += 1
                            continue
                        result.append(char)
                        i += 1
                    return ''.join(result)
                
                content = escape_newlines_in_strings(content)
                
                print(f"Cleaned content for JSON parsing: '{content}'")
                
                try:
                    report_data = json.loads(content)
                except json.JSONDecodeError as json_error:
                    print(f"JSON parsing error: {str(json_error)}")
                    # Extract fraud identifier from original data for fallback
                    fraud_id = extract_fraud_identifier(event_data)
                    fraud_type = extract_fraud_type(event_data)
                    
                    report_data = {
                        "incident_report": f"Fraud Alert: {fraud_type} Detected\\n\\nA suspicious transaction pattern was detected.\\n\\nPlease investigate further.",
                        "severity": 2,
                        "fraud_identifier": fraud_id
                    }
                
            except Exception as nova_error:
                print(f"Model response failed: {str(nova_error)}")
                fraud_id = extract_fraud_identifier(event_data)
                print(f"Extracted fraud identifier for fallback: {fraud_id}")
                raise nova_error
            
            response_body = {
                'TEXT': {
                    'body': json.dumps({
                        'incident_report': report_data.get('incident_report', 'Report generated'),
                        'severity': str(report_data.get('severity', '1')),
                        'fraud_identifier': report_data.get('fraud_identifier', 'Unknown')
                    })
                }
            }
            print(f"Response body created: {response_body}")
            
        elif function == 'sendNotification':
            severity = params.get('severity', '1')
            if severity == '2':
                if TOPIC_ARN:
                    message_body = params.get('message', 'Fraud incident detected - Direct evidence of fraudulent activity')
                    
                    subject = params.get('subject', 'Fraud Alert - Transaction Anomaly Detected')
                    
                    sns_client.publish(
                        TopicArn=TOPIC_ARN,
                        Message=message_body,
                        Subject=subject
                    )
                status = 'notification sent'
            else:
                status = 'notification skipped - severity below threshold'
                
            response_body = {
                'TEXT': {
                    'body': json.dumps({
                        'status': status,
                        'severity': severity
                    })
                }
            }
        else:
            response_body = {
                'TEXT': {
                    'body': json.dumps({'error': f'Unknown function: {function}'})
                }
            }
        
        return {
            'messageVersion': '1.0',
            'response': {
                'actionGroup': actionGroup,
                'function': function,
                'functionResponse': {
                    'responseBody': response_body
                }
            }
        }
    
    except Exception as e:
        print(f"Error: {str(e)}")
        return {
            'messageVersion': '1.0',
            'response': {
                'actionGroup': event.get('actionGroup', 'unknown'),
                'function': event.get('function', 'unknown'),
                'functionResponse': {
                    'responseBody': {
                        'TEXT': {
                            'body': json.dumps({'error': str(e)})
                        }
                    }
                }
            }
        }

def extract_fraud_identifier(event_data):
    """Extract the primary fraud identifier from event data"""
    if 'Suspicious Device:' in event_data:
        return event_data.split('Suspicious Device: ')[1].split('\n')[0] if 'Suspicious Device: ' in event_data else "Unknown"
    elif 'Fraudulent Card:' in event_data:
        return event_data.split('Fraudulent Card: ')[1].split('\n')[0] if 'Fraudulent Card: ' in event_data else "Unknown"
    elif 'attacker_id' in event_data:
        return event_data.split('attacker_id')[1].split(',')[0].strip(' ":') if 'attacker_id' in event_data else "Unknown"
    else:
        return "Unknown"

def extract_fraud_type(event_data):
    """Extract the fraud type from event data"""
    if 'Card Testing' in event_data:
        return "Card Testing Fraud"
    elif 'Velocity Fraud' in event_data:
        return "Velocity Fraud"
    else:
        return "Financial Fraud"