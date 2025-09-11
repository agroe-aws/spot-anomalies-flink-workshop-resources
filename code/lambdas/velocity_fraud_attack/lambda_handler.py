# License: MIT-0

import json
import time
import random
import os
import socket
import hashlib

from kafka import KafkaProducer
from kafka.errors import KafkaError
from aws_msk_iam_sasl_signer import MSKAuthTokenProvider

def generate_transaction_id():
    """Generate unique transaction ID"""
    return f"TXN-{hashlib.md5(str(random.random()).encode()).hexdigest()[:12].upper()}"

def generate_device_id():
    """Generate device identifier"""
    return f"DEV-{hashlib.md5(str(random.random()).encode()).hexdigest()[:8].upper()}"

def generate_geographic_locations():
    """Generate geographically impossible locations for velocity fraud"""
    return [
        {"city": "New York", "state": "NY", "country": "US"},
        {"city": "London", "state": "ENG", "country": "UK"},
        {"city": "Tokyo", "state": "TKY", "country": "JP"},
        {"city": "Sydney", "state": "NSW", "country": "AU"}
    ]

class MSKTokenProvider:
    def token(self):
        token, _ = MSKAuthTokenProvider.generate_auth_token(os.environ["AWS_REGION"])
        return token

def lambda_handler(event, context):
    """Generate velocity fraud attack - same card, impossible geographic velocity"""
    
    print(f"BOOTSTRAP_SERVER: {os.environ.get('BOOTSTRAP_SERVER', 'NOT_SET')}")
    print(f"TOPIC_NAME: {os.environ.get('TOPIC_NAME', 'NOT_SET')}")
    print(f"AWS_REGION: {os.environ.get('AWS_REGION', 'NOT_SET')}")
    
    tp = MSKTokenProvider()
    locations = generate_geographic_locations()
    
    producer = KafkaProducer(
        bootstrap_servers=os.environ["BOOTSTRAP_SERVER"],
        security_protocol="SASL_SSL",
        sasl_mechanism="OAUTHBEARER",
        sasl_oauth_token_provider=tp,
        client_id=socket.gethostname(),
        key_serializer=lambda key: key.encode("utf-8"),
        value_serializer=lambda value: json.dumps(value).encode("utf-8"),
        api_version=(2, 0, 0)
    )
    
    topic = os.environ["TOPIC_NAME"]
    
    # Velocity fraud: same card used in impossible geographic locations
    fraud_card = "4532"  # Same card for all transactions
    base_time = int(time.time() * 1000)
    
    for i in range(30):
        current_time_ms = base_time + (i * 300000)  # 5 minutes apart
        location = locations[i % len(locations)]  # Cycle through impossible locations
        
        data = {
            "event_type": "PURCHASE",
            "transaction_id": generate_transaction_id(),
            "card_number": fraud_card,
            "card_network": "VISA",
            "amount": round(random.uniform(50.00, 500.00), 2),
            "currency": "USD",
            "merchant_id": f"MER-{generate_device_id()}",
            "merchant_name": f"Store {location['city']}",
            "merchant_category_code": "5411",
            "merchant_category_name": "Grocery Stores",
            "device_id": generate_device_id(),
            "location_city": location["city"],
            "location_state": location["state"],
            "location_country": location["country"],
            "timestamp_start": current_time_ms - 10,
            "timestamp_end": current_time_ms,
            "packets": random.randint(5, 12),
            "bytes": random.randint(800, 1500),
            "writer_id": f"POS-{generate_device_id()}-x1",
            "text": f"Velocity fraud: Card {fraud_card} used in {location['city']}, {location['country']} - impossible travel time"
        }
        
        producer.send(topic, key=str(i), value=data)
    
    producer.flush()
    producer.close()
    
    return {"statusCode": 200, "body": "Generated 30 velocity fraud attack events"}