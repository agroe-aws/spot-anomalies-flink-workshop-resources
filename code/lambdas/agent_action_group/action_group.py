import json
import boto3
import os
from prompt_templates import SYSTEM_PROMPT, SUMMARIZATION_TEMPLATE_PARAGRAPH

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
            event_data = params.get('eventData', 'No event data provided')
            
            prompt = f"{SYSTEM_PROMPT}\n\n{SUMMARIZATION_TEMPLATE_PARAGRAPH.format(input_event=event_data)}"

            request_body = {
                "schemaVersion": "messages-v1",
                "messages": [
                    {
                        "role": "user", 
                        "content": [{"text": prompt}]
                    }
                ],
                "inferenceConfig": {
                    "maxTokens": 2048,
                    "temperature": 0
                }
            }

            response = bedrock_runtime.invoke_model(
                modelId="us.amazon.nova-micro-v1:0",
                body=json.dumps(request_body)
            )
            
            result = json.loads(response['body'].read())
            content = result['output']['message']['content'][0]['text']
            
            try:
                report_data = json.loads(content)
                response_body = {
                    'TEXT': {
                        'body': json.dumps({
                            'incident_report': report_data.get('incident_report', 'Report generated'),
                            'severity': str(report_data.get('severity', '1')),
                            'ip_address': report_data.get('ip_address', 'Unknown')
                        })
                    }
                }
            except json.JSONDecodeError:
                response_body = {
                    'TEXT': {
                        'body': json.dumps({
                            'incident_report': content,
                            'severity': '1',
                            'ip_address': 'Unknown'
                        })
                    }
                }
            
        elif function == 'sendNotification':
            severity = params.get('severity', '1')
            if severity == '2':
                if TOPIC_ARN:
                    message_body = params.get('message', 'Security incident detected - Direct evidence of malicious intent')
                    
                    subject = params.get('subject', 'Security Alert - Network Anomaly Detected')
                    
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
