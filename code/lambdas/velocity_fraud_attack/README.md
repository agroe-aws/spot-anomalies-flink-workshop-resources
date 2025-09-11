# Velocity Fraud Attack Lambda

Generates velocity fraud patterns for financial fraud detection.

## Attack Pattern
- **Type**: Geographic Velocity Fraud
- **Volume**: 30 transactions per invocation
- **Timing**: 5-minute intervals
- **Characteristics**:
  - Same card number for all transactions
  - Geographically impossible locations (NY → London → Tokyo → Sydney)
  - Normal transaction amounts ($50-$500)
  - Different merchants in each location

## Anomaly Indicators
- Same card used in multiple countries within hours
- Impossible travel time between locations
- Geographic velocity exceeding human travel capabilities

## Environment Variables
- `BOOTSTRAP_SERVER`: MSK cluster endpoint
- `TOPIC_NAME`: Kafka topic name
- `AWS_REGION`: AWS region for authentication

## Detection Logic
Flink applications should detect:
1. Same card_number in multiple countries/cities
2. Time intervals too short for physical travel
3. Geographic distance vs. time analysis
4. Velocity calculations exceeding realistic travel speeds