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
            
            fraud_type = jsg_msg.get('fraud_type', 'UNKNOWN')
            attacker_id = jsg_msg['attacker_id']
            
            logger.info(f"Processing {fraud_type} fraud from {attacker_id} at {datetime.fromtimestamp(jsg_msg['attack_start_time']).isoformat()}")
            
            if fraud_type == "CARD_TESTING":
                event_data = f"""Card Testing Fraud Detection:
- Attack Start Time: {datetime.fromtimestamp(jsg_msg['attack_start_time']).isoformat()}Z
- Attack End Time: {datetime.fromtimestamp(jsg_msg['attack_end_time']).isoformat()}Z  
- Suspicious Device: {jsg_msg['attacker_id']}
- Target Merchant: {jsg_msg['target_ip']}
- Transaction Count: {jsg_msg['transaction_count']}
- Unique Cards Tested: {jsg_msg['card_number']}
- Total Amount: ${jsg_msg['total_amount']:.2f}
- Average Amount: ${jsg_msg['avg_amount']:.2f}
- Velocity Score: {jsg_msg['velocity_score']:.1f}
- Location: {jsg_msg['locations']}
- Attack Duration: {jsg_msg['attack_end_time'] - jsg_msg['attack_start_time']:.3f} seconds"""
            
            elif fraud_type == "VELOCITY_FRAUD":
                event_data = f"""Velocity Fraud Detection:
- Attack Start Time: {datetime.fromtimestamp(jsg_msg['attack_start_time']).isoformat()}Z
- Attack End Time: {datetime.fromtimestamp(jsg_msg['attack_end_time']).isoformat()}Z  
- Fraudulent Card: {jsg_msg['attacker_id']}
- Locations Used: {jsg_msg['target_ip']}
- Transaction Count: {jsg_msg['transaction_count']}
- Total Amount: ${jsg_msg['total_amount']:.2f}
- Average Amount: ${jsg_msg['avg_amount']:.2f}
- Velocity Score: {jsg_msg['velocity_score']:.1f}
- Geographic Locations: {jsg_msg['locations']}
- Attack Duration: {jsg_msg['attack_end_time'] - jsg_msg['attack_start_time']:.3f} seconds"""
            
            else:
                event_data = f"""Unknown Fraud Pattern:
- Attack Start Time: {datetime.fromtimestamp(jsg_msg['attack_start_time']).isoformat()}Z
- Attack End Time: {datetime.fromtimestamp(jsg_msg['attack_end_time']).isoformat()}Z  
- Attacker ID: {jsg_msg['attacker_id']}
- Fragment Count: {jsg_msg['fragment_count']}
- Average Packets: {jsg_msg['avg_packets']}"""

            # Retry logic for throttling
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    logger.info(f"Calling agent {AGENT_ID}/{AGENT_ALIAS_ID} - Attempt {attempt + 1}")
                    response = bedrock_agent_runtime.invoke_agent(
                        agentId=AGENT_ID,
                        agentAliasId=AGENT_ALIAS_ID,
                        sessionId=f'fraud-{int(time.time())}-{attempt}', 
                        inputText=f"Analyze this financial fraud event: {event_data}"
                    )
                    
                    # Process streaming response
                    agent_response = ""
                    chunk_count = 0
                    try:
                        for event_chunk in response['completion']:
                            chunk_count += 1
                            if 'chunk' in event_chunk:
                                chunk = event_chunk['chunk']
                                if 'bytes' in chunk:
                                    agent_response += chunk['bytes'].decode('utf-8')
                    except Exception as stream_error:
                        logger.error(f"Stream failed after {chunk_count} chunks: {str(stream_error)}")
                        pass
                    
                    logger.info(f"SUCCESS: Agent completed, {chunk_count} chunks")
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
                        
                except Exception as agent_error:
                    logger.error(f"Agent error (attempt {attempt + 1}): {str(agent_error)}")
                    if attempt < max_retries - 1:
                        time.sleep(2 ** attempt)
                    else:
                        responses.append({"anomaly": jsg_msg, "error": str(agent_error)})
                        break
    
    return responses