# Card Testing Attack Lambda

Generates card testing fraud patterns for financial fraud detection.

## Attack Pattern
- **Type**: Card Testing/Carding Attack
- **Volume**: 50 transactions per invocation
- **Timing**: 100ms intervals (very rapid)
- **Characteristics**:
  - Same merchant and device
  - Multiple different card numbers (sequential pattern)
  - Small transaction amounts ($0.01-$1.99)
  - Online retail merchants

## Anomaly Indicators
- High transaction velocity from single device
- Sequential card number patterns
- Consistent small amounts
- Same merchant for all transactions

## Environment Variables
- `BOOTSTRAP_SERVER`: MSK cluster endpoint
- `TOPIC_NAME`: Kafka topic name
- `AWS_REGION`: AWS region for authentication

## Detection Logic
Flink applications should detect:
1. Rapid transactions from same device_id
2. Multiple different card numbers in short timeframe
3. Consistent small transaction amounts
4. High frequency at single merchant