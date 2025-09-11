# License: MIT-0

import json
import random
import os
import socket
import hashlib
import time
from decimal import Decimal, ROUND_HALF_UP

from faker import Faker
from faker.providers import credit_card, person, address, company
from kafka import KafkaProducer
from kafka.errors import KafkaError
from aws_msk_iam_sasl_signer import MSKAuthTokenProvider

# For IAM auth
class MSKTokenProvider:
    def token(self):
        token, _ = MSKAuthTokenProvider.generate_auth_token(
            os.environ["AWS_REGION"])
        return token

def generate_transaction_id():
    """Generate unique transaction ID"""
    return f"TXN-{hashlib.md5(str(random.random()).encode()).hexdigest()[:12].upper()}"

def generate_device_id():
    """Generate device identifier for card reader/ATM"""
    return f"DEV-{hashlib.md5(str(random.random()).encode()).hexdigest()[:8].upper()}"

def generate_merchant_categories():
    """Generate list of merchant category codes and names"""
    return [
        {"code": "5411", "name": "Grocery Stores"},
        {"code": "5812", "name": "Restaurants"},
        {"code": "5541", "name": "Gas Stations"},
        {"code": "5311", "name": "Department Stores"},
        {"code": "5999", "name": "Retail"},
        {"code": "6011", "name": "ATM Cash Withdrawal"},
        {"code": "5732", "name": "Electronics"},
        {"code": "5814", "name": "Fast Food"},
        {"code": "4111", "name": "Transportation"},
        {"code": "5912", "name": "Pharmacy"}
    ]

def generate_card_networks():
    """Generate card network types"""
    return ["VISA", "MASTERCARD", "AMEX", "DISCOVER"]

def produce_normal_transactions():
    """Produce normal financial transaction events continuously"""
    # Log environment variables
    print(f"BOOTSTRAP_SERVER: {os.environ.get('BOOTSTRAP_SERVER', 'NOT_SET')}")
    print(f"TOPIC_NAME: {os.environ.get('TOPIC_NAME', 'NOT_SET')}")
    print(f"AWS_REGION: {os.environ.get('AWS_REGION', 'NOT_SET')}")
    
    fake = Faker()
    fake.add_provider(credit_card)
    fake.add_provider(person)
    fake.add_provider(address)
    fake.add_provider(company)
    tp = MSKTokenProvider()

    merchant_categories = generate_merchant_categories()
    card_networks = generate_card_networks()
    transaction_types = ["PURCHASE", "WITHDRAWAL", "REFUND"]
    currencies = ["USD", "EUR", "GBP", "CAD"]
    
    # Log producer configuration
    producer_config = {
        "bootstrap_servers": os.environ["BOOTSTRAP_SERVER"],
        "security_protocol": "SASL_SSL",
        "sasl_mechanism": "OAUTHBEARER",
        "client_id": socket.gethostname()
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
        linger_ms=10,
        batch_size=262144,
    )

    topic = os.environ["TOPIC_NAME"]
    
    while True:
        current_time_ms = int(time.time() * 1000)
        merchant = random.choice(merchant_categories)
        
        # Generate realistic transaction amount based on merchant type
        if merchant["code"] == "6011":  # ATM
            amount = random.choice([20, 40, 60, 80, 100, 200])
        elif merchant["code"] in ["5812", "5814"]:  # Restaurants/Fast Food
            amount = round(random.uniform(8.50, 85.00), 2)
        elif merchant["code"] == "5541":  # Gas Stations
            amount = round(random.uniform(25.00, 75.00), 2)
        else:  # Other retail
            amount = round(random.uniform(5.00, 250.00), 2)
        
        data = {
            "event_type": random.choice(transaction_types),
            "transaction_id": generate_transaction_id(),
            "card_number": fake.credit_card_number()[-4:],  # Last 4 digits only
            "card_network": random.choice(card_networks),
            "amount": amount,
            "currency": random.choice(currencies),
            "merchant_id": f"MER-{generate_device_id()}",
            "merchant_name": fake.company(),
            "merchant_category_code": merchant["code"],
            "merchant_category_name": merchant["name"],
            "device_id": generate_device_id(),
            "location_city": fake.city(),
            "location_state": fake.state_abbr(),
            "location_country": "US",
            "timestamp_start": current_time_ms - 10,
            "timestamp_end": current_time_ms,
            "packets": random.randint(5, 15),  # API calls/network packets
            "bytes": random.randint(256, 2048),  # Transaction data size
            "writer_id": f"POS-{generate_device_id()}-x{random.randint(1, 5)}",
            "text": f"Normal {merchant['name']} transaction ${amount} from card ending {fake.credit_card_number()[-4:]}"
        }
        
        producer.send(topic, key=str(random.randint(1, 10000)), value=data)
        time.sleep(0.1)  # 10 events per second

if __name__ == "__main__":
    produce_normal_transactions()