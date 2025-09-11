# Financial Transaction Producer for Fraud Detection

This producer generates realistic debit card transaction events for fraud detection use cases, replacing the original network flow log producer.

## Key Features

### Financial Domain Data
- **Transaction Types**: PURCHASE, WITHDRAWAL, REFUND
- **Card Networks**: VISA, MASTERCARD, AMEX, DISCOVER
- **Merchant Categories**: 10 realistic categories (Grocery, Restaurants, Gas Stations, etc.)
- **Realistic Amounts**: Context-aware pricing (ATM: $20-200, Restaurants: $8.50-85, etc.)
- **Geographic Data**: US cities, states, and merchant locations

### Event Schema
```json
{
  "event_type": "PURCHASE",
  "transaction_id": "TXN-A1B2C3D4E5F6",
  "card_number": "1234",
  "card_network": "VISA",
  "amount": 45.67,
  "currency": "USD",
  "merchant_id": "MER-DEV12345678",
  "merchant_name": "Sample Store Inc",
  "merchant_category_code": "5411",
  "merchant_category_name": "Grocery Stores",
  "device_id": "DEV-ABC12345",
  "location_city": "Seattle",
  "location_state": "WA",
  "location_country": "US",
  "timestamp_start": 1703123456789,
  "timestamp_end": 1703123456799,
  "packets": 8,
  "bytes": 1024,
  "writer_id": "POS-DEV12345678-x3",
  "text": "Normal Grocery Stores transaction $45.67 from card ending 1234"
}
```

## Setup and Usage

### Local Development
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r financial_requirements.txt
```

### Test Functions
```bash
python test_financial_functions.py
```

### Run Producer
```bash
export BOOTSTRAP_SERVER="your-kafka-server:9092"
export TOPIC_NAME="financial-transactions"
export AWS_REGION="us-east-1"
python financial_transaction_producer.py
```

### Docker Build and Run
```bash
# Build
docker build -f financial_dockerfile -t financial-transaction-producer .

# Run
docker run -i \
  -e BOOTSTRAP_SERVER="your-kafka-server:9092" \
  -e TOPIC_NAME="financial-transactions" \
  -e AWS_REGION="us-east-1" \
  financial-transaction-producer:latest
```

## Production Configuration

### Event Rate
- Default: 10 events/second (0.1s sleep)
- Modify `time.sleep()` value to adjust rate

### ECS Deployment
The Docker container is ECS-ready with:
- MSK IAM authentication
- AWS CLI for troubleshooting
- Network diagnostic tools
- Proper startup logging

### Environment Variables
- `BOOTSTRAP_SERVER`: MSK cluster endpoint
- `TOPIC_NAME`: Kafka topic for transactions
- `AWS_REGION`: AWS region for MSK authentication

## Fraud Detection Use Cases

This producer generates normal baseline transactions suitable for detecting:
- **Velocity Fraud**: Unusual transaction frequency
- **Geographic Fraud**: Transactions from impossible locations
- **Amount Fraud**: Unusual spending patterns
- **Merchant Fraud**: Suspicious merchant interactions
- **Time-based Fraud**: Transactions at unusual hours

The generated data maintains realistic patterns while providing sufficient variety for ML model training.