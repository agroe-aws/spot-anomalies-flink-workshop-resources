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

def generate_card_testing_pattern():
    """Generate card numbers for testing attack (sequential or similar patterns)"""
    base_card = random.randint(4000, 4999)  # Visa range
    return [f"{base_card}{str(i).zfill(4)}" for i in range(10)]

def generate_suspicious_merchants():
    """Generate merchants commonly used for card testing"""
    return [
        {"id": "MER-ONLINE001", "name": "QuickPay Digital", "category": "5999", "category_name": "Online Retail"},
        {"id": "MER-ONLINE002", "name": "FastCheck Services", "category": "5999", "category_name": "Online Retail"},
        {"id": "MER-ONLINE003", "name": "VerifyCard Inc", "category": "5999", "category_name": "Online Retail"}
    ]

class MSKTokenProvider:
    def token(self):
        token, _ = MSKAuthTokenProvider.generate_auth_token(os.environ["AWS_REGION"])
        return token

def lambda_handler(event, context):
    """Generate card testing attack pattern - 50 rapid small transactions"""
    
    print(f"BOOTSTRAP_SERVER: {os.environ.get('BOOTSTRAP_SERVER', 'NOT_SET')}")
    print(f"TOPIC_NAME: {os.environ.get('TOPIC_NAME', 'NOT_SET')}")
    print(f"AWS_REGION: {os.environ.get('AWS_REGION', 'NOT_SET')}")
    
    tp = MSKTokenProvider()
    test_cards = generate_card_testing_pattern()
    suspicious_merchants = generate_suspicious_merchants()
    
    producer_config = {
        "bootstrap_servers": os.environ["BOOTSTRAP_SERVER"],
        "security_protocol": "SASL_SSL",
        "sasl_mechanism": "OAUTHBEARER",
        "client_id": socket.gethostname(),
        "api_version": (2, 0, 0)
    }
    print(f"Kafka Producer Config: {producer_config}")
    
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
    
    # Card testing attack: same merchant, rapid small transactions, different cards
    attack_merchant = random.choice(suspicious_merchants)
    attack_device = generate_device_id()
    base_time = int(time.time() * 1000)
    
    for i in range(50):
        current_time_ms = base_time + (i * 100)  # 100ms apart - very rapid
        test_card = random.choice(test_cards)
        
        data = {
            "event_type": "PURCHASE",
            "transaction_id": generate_transaction_id(),
            "card_number": test_card[-4:],
            "card_network": "VISA",
            "amount": random.choice([0.01, 0.99, 1.00, 1.99]),  # Small test amounts
            "currency": "USD",
            "merchant_id": attack_merchant["id"],
            "merchant_name": attack_merchant["name"],
            "merchant_category_code": attack_merchant["category"],
            "merchant_category_name": attack_merchant["category_name"],
            "device_id": attack_device,  # Same device for all transactions
            "location_city": "Las Vegas",
            "location_state": "NV",
            "location_country": "US",
            "timestamp_start": current_time_ms - 10,
            "timestamp_end": current_time_ms,
            "packets": random.randint(3, 8),
            "bytes": random.randint(512, 1024),
            "writer_id": f"POS-{attack_device}-x1",
            "text": f"Card testing attack: ${data['amount']} transaction from card ending {test_card[-4:]} at {attack_merchant['name']}"
        }
        
        producer.send(topic, key=str(i), value=data)
    
    producer.flush()
    producer.close()
    
    return {"statusCode": 200, "body": "Generated 50 card testing attack events"}