import boto3
import os
import base64
import json
import time
from datetime import datetime
from connections import tracer, logger, metrics
from aws_lambda_powertools.metrics import MetricUnit
from botocore.exceptions import ClientError

AGENT_ID = os.environ["AGENT_ID"]
AGENT_ALIAS_ID = os.environ["AGENT_ALIAS_ID"]
REGION_NAME = os.environ["REGION_NAME"]

bedrock_agent_runtime = boto3.client("bedrock-agent-runtime", region_name=REGION_NAME)

@logger.inject_lambda_context(log_event=True, clear_state=True)
@tracer.capture_lambda_handler
@metrics.log_metrics(capture_cold_start_metric=True)
def lambda_handler(event, context):
    
    metrics.add_metric(name="TotalInvocations", unit=MetricUnit.Count, value=1)
    
    records = event.get("records")
    responses = []
    
    for topic_key in records.keys():
        messages = records.get(topic_key)
        
        for msg in messages:
            jsg_msg = json.loads(
                base64.b64decode(msg["value"]).decode("utf-8"), strict=False
            )
            
            logger.info(f"Processing anomaly: {jsg_msg}")
            
            # Format anomaly data for the original template
            event_data = f"""Fragment Attack Detection:
- Attack Start Time: {datetime.fromtimestamp(jsg_msg['attack_start_time']).isoformat()}Z
- Attack End Time: {datetime.fromtimestamp(jsg_msg['attack_end_time']).isoformat()}Z  
- Attacker IP: {jsg_msg['attacker_id']}
- Target IP: {jsg_msg['target_ip']}
- Fragment Count: {jsg_msg['fragment_count']}
- Average Packets: {jsg_msg['avg_packets']}
- Average Fragment Size: {jsg_msg['avg_fragment_size']:.2f}
- Size Reduction Percentage: {jsg_msg['size_reduction_percent']:.1f}%
- Attack Duration: {jsg_msg['attack_end_time'] - jsg_msg['attack_start_time']:.3f} seconds"""

            # Retry logic for throttling
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    response = bedrock_agent_runtime.invoke_agent(
                        agentId=AGENT_ID,
                        agentAliasId=AGENT_ALIAS_ID,
                        sessionId=f'anomaly-{context.aws_request_id}-{attempt}',
                        inputText=f"Analyze this network security event and generate an incident report using the established template: {event_data}"
                    )
                    
                    # Process streaming response
                    agent_response = ""
                    for event_chunk in response['completion']:
                        if 'chunk' in event_chunk:
                            chunk = event_chunk['chunk']
                            if 'bytes' in chunk:
                                agent_response += chunk['bytes'].decode('utf-8')
                    
                    logger.info(f"Agent analysis complete")
                    responses.append({"anomaly": jsg_msg, "agent_response": agent_response})
                    break  # Success, exit retry loop
                    
                except ClientError as e:
                    if e.response['Error']['Code'] == 'throttlingException':
                        if attempt < max_retries - 1:
                            wait_time = (2 ** attempt) + 1  # Exponential backoff
                            logger.warning(f"Throttled, retrying in {wait_time}s (attempt {attempt + 1})")
                            time.sleep(wait_time)
                        else:
                            logger.error(f"Max retries exceeded for throttling")
                            metrics.add_metric(name="ThrottlingErrors", unit=MetricUnit.Count, value=1)
                            responses.append({"anomaly": jsg_msg, "error": "throttled"})
                    else:
                        raise e
    
    return responses
