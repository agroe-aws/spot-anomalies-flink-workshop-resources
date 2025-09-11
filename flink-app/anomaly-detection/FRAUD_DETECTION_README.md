# Financial Fraud Detection Flink Application

## Overview
Customized Flink application for detecting financial fraud patterns, replacing the original network fragmentation attack detection.

## Fraud Detection Patterns

### 1. Card Testing Detection
**Pattern**: Multiple small transactions from same device
- **Key Field**: `device_id`
- **Conditions**: 
  - Event type = "PURCHASE"
  - Amount < $5.00
  - 10-50 transactions within 5 minutes
- **Output**: Card testing fraud with unique card count and velocity metrics

### 2. Velocity Fraud Detection  
**Pattern**: Same card used in multiple geographic locations
- **Key Field**: `card_number`
- **Conditions**:
  - Event type = "PURCHASE" 
  - Amount > $20.00
  - 3-10 transactions within 2 hours
- **Output**: Velocity fraud with geographic location analysis

## Input Schema (FinancialEvent)
```json
{
  "event_type": "PURCHASE",
  "transaction_id": "TXN-ABC123",
  "card_number": "1234",
  "amount": 45.67,
  "merchant_id": "MER-XYZ789",
  "device_id": "DEV-ABC123",
  "location_city": "Seattle",
  "location_country": "US",
  "timestamp_start": 1703123456789
}
```

## Output Schema (FraudResult)
Maintains compatibility with invoke agent lambda while adding fraud-specific fields:

### Legacy Fields (for compatibility)
- `attack_start_time`: Fraud detection start time
- `attack_end_time`: Fraud detection end time  
- `attacker_id`: Primary fraud identifier (device_id or card_number)
- `target_ip`: Target entity (merchant_id or locations)
- `fragment_count`: Transaction count
- `avg_packets`: Average metric
- `avg_fragment_size`: Average transaction amount
- `size_reduction_percent`: Fraud intensity percentage

### Financial Fields
- `fraud_type`: "CARD_TESTING" or "VELOCITY_FRAUD"
- `card_number`: Card identifier or count
- `merchant_id`: Merchant identifier
- `device_id`: Device identifier
- `transaction_count`: Number of transactions
- `total_amount`: Total transaction amount
- `avg_amount`: Average transaction amount
- `velocity_score`: Fraud velocity metric
- `locations`: Geographic locations involved

## CEP Pattern Logic

### Card Testing Pattern
```java
Pattern.<FinancialEvent>begin("cardTesting")
    .where(event -> "PURCHASE".equals(event.getEventType()) && 
                   event.getAmount() < 5.0)
    .times(10, 50)
    .within(Time.minutes(5))
```

### Velocity Fraud Pattern  
```java
Pattern.<FinancialEvent>begin("velocity")
    .where(event -> "PURCHASE".equals(event.getEventType()) && 
                   event.getAmount() > 20.0)
    .times(3, 10)
    .within(Time.hours(2))
```

## Configuration
- **Property Group**: `FraudDetection`
- **Source Topic**: Financial transaction events
- **Sink Topic**: Fraud detection results
- **Parallelism**: 6 (local environment)

## Integration
- **Input**: MSK topic with financial transaction events
- **Output**: MSK topic consumed by `fraud_summarization.py` lambda
- **Agent**: Bedrock agent analyzes fraud patterns and generates reports

## Deployment
1. Update `application.properties` with fraud detection configuration
2. Build with Maven: `mvn compile`
3. Deploy to Kinesis Analytics or run locally
4. Configure MSK topics and IAM permissions