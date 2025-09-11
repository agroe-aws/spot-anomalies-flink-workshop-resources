#!/usr/bin/env python3

import sys
sys.path.append('.')

from financial_transaction_producer import generate_transaction_id, generate_device_id, generate_merchant_categories, generate_card_networks
import random
import datetime
from faker import Faker
from faker.providers import credit_card, person, address, company

# Test the functions
print("Testing financial transaction producer functions:")

fake = Faker()
fake.add_provider(credit_card)
fake.add_provider(person)
fake.add_provider(address)
fake.add_provider(company)

merchant_categories = generate_merchant_categories()
card_networks = generate_card_networks()

print(f"Generated {len(merchant_categories)} merchant categories: {[m['name'] for m in merchant_categories[:3]]}")
print(f"Card networks: {card_networks}")

print("\nTesting financial transaction generation:")
for i in range(3):
    current_time_ms = int(datetime.datetime.now().timestamp() * 1000)
    merchant = random.choice(merchant_categories)
    
    data = {
        "event_type": random.choice(["PURCHASE", "WITHDRAWAL", "REFUND"]),
        "transaction_id": generate_transaction_id(),
        "card_number": fake.credit_card_number()[-4:],
        "card_network": random.choice(card_networks),
        "amount": round(random.uniform(5.00, 250.00), 2),
        "currency": "USD",
        "merchant_name": fake.company(),
        "merchant_category_code": merchant["code"],
        "device_id": generate_device_id(),
        "location_city": fake.city(),
        "timestamp_start": current_time_ms
    }
    print(f"Transaction {i+1}: {data}")

print("\nFinancial transaction producer test completed successfully!")