# Financial Fraud Detection Lambda Functions

## Overview
Customized anomaly injection lambda functions for financial fraud detection, replacing the original network fragmentation attack patterns.

## Available Fraud Patterns

### 1. Card Testing Attack (`card_testing_attack/`)
**Pattern**: Rapid small transactions testing stolen card numbers
- **Volume**: 50 events per invocation
- **Timing**: 100ms intervals (extremely rapid)
- **Key Indicators**:
  - Same merchant_id and device_id
  - Different card numbers (sequential patterns)
  - Small amounts ($0.01-$1.99)
  - High velocity from single point

### 2. Velocity Fraud Attack (`velocity_fraud_attack/`)
**Pattern**: Same card used in geographically impossible locations
- **Volume**: 30 events per invocation  
- **Timing**: 5-minute intervals
- **Key Indicators**:
  - Same card_number across locations
  - Impossible travel times (NY→London→Tokyo→Sydney)
  - Normal transaction amounts
  - Geographic velocity analysis

## Integration with Original Workshop

### Maintained Components
- ✅ MSK IAM authentication
- ✅ Kafka producer setup
- ✅ Lambda function structure
- ✅ Environment variable configuration
- ✅ Error handling and logging

### Replaced Components
- ❌ Network IP generation → Financial transaction IDs
- ❌ Fragmentation logic → Fraud pattern logic  
- ❌ Network protocols → Card networks and merchants
- ❌ Packet/byte counts → Transaction metadata
- ❌ Attack signatures → Fraud indicators

## Event Schema Compatibility
Both functions generate events matching the financial transaction schema:
```json
{
  "event_type": "PURCHASE",
  "transaction_id": "TXN-ABC123DEF456",
  "card_number": "1234",
  "amount": 45.67,
  "merchant_id": "MER-XYZ789",
  "device_id": "DEV-ABC12345",
  "location_city": "New York",
  "timestamp_start": 1703123456789
}
```

## Flink Detection Logic
The generated anomalies should be detectable by Flink applications using:

**Card Testing Detection**:
- Window-based counting of transactions per device_id
- Distinct card_number count per time window
- Transaction amount pattern analysis
- Velocity thresholds

**Velocity Fraud Detection**:
- Geographic distance calculations
- Time-based velocity analysis  
- Same card_number across locations
- Travel time feasibility checks

## Deployment
Deploy as standard Lambda functions with MSK trigger or manual invocation for testing anomaly detection systems.