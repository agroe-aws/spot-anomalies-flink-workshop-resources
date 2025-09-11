# Financial Fraud Detection Agent Action Group

## Overview
Customized Bedrock agent action group Lambda function for financial fraud detection, replacing the original network security focus.

## Key Transformations

### Domain-Specific Changes
**Original (Network Security)**:
- Analyzed network fragmentation attacks
- Extracted IP addresses as primary identifiers
- Generated network security alerts
- Used cybersecurity terminology

**New (Financial Fraud)**:
- Analyzes card testing and velocity fraud patterns
- Extracts card numbers, device IDs, or account IDs as primary identifiers
- Generates fraud investigation alerts
- Uses financial fraud terminology

### Functions

#### 1. `generateTemplate`
**Purpose**: Analyze fraud data and generate structured incident reports

**Input Processing**:
- Receives fraud detection data from Flink application
- Sanitizes fraud-specific terminology for Bedrock model
- Extracts primary fraud identifier (card/device/account)

**Data Sanitization**:
```python
sanitized_data = event_data.replace('Card Testing Fraud Detection', 'Transaction Pattern Analysis')
sanitized_data = sanitized_data.replace('Velocity Fraud Detection', 'Geographic Transaction Analysis')
sanitized_data = sanitized_data.replace('Fraudulent Card', 'Suspicious Card')
```

**Output Schema**:
```json
{
  "incident_report": "Fraud Alert: Card Testing Detected...",
  "severity": 2,
  "fraud_identifier": "DEV-ABC123"
}
```

#### 2. `sendNotification`
**Purpose**: Send SNS notifications for high-severity fraud incidents

**Trigger Conditions**:
- Severity level 2 (transaction count > 20 or velocity score > 5)
- Fraud incidents requiring immediate investigation

**Notification Content**:
- Subject: "Fraud Alert - Transaction Anomaly Detected"
- Message: Fraud incident details with investigation recommendations

### Identifier Extraction Logic

**Priority Order**:
1. **Device ID**: For card testing attacks (`Suspicious Device: DEV-ABC123`)
2. **Card Number**: For velocity fraud (`Fraudulent Card: 4532`)
3. **Attacker ID**: From JSON structure (`"attacker_id": "value"`)
4. **Fallback**: "Unknown"

### Severity Calculation

**High Severity (Level 2)**:
- Transaction count > 20
- Velocity score > 5
- Triggers SNS notification

**Low Severity (Level 1)**:
- Below threshold values
- No notification sent

### Integration Points

**Input Source**: 
- Flink `FraudResult` objects from fraud detection application
- JSON structure with fraud-specific fields

**Output Destination**:
- Bedrock agent for report generation
- SNS topic for high-severity alerts
- Fraud investigation teams

**Bedrock Model**:
- Uses Amazon Nova Micro for fraud analysis
- Financial fraud-specific prompts and context
- JSON response parsing with fraud identifiers

### Error Handling

**Fallback Mechanisms**:
- JSON parsing errors → Generate basic fraud alert
- Model failures → Extract identifiers from raw data
- Missing data → Use "Unknown" placeholders

**Maintained Features**:
- ✅ AWS service integrations (Bedrock, SNS)
- ✅ Error handling and retry logic
- ✅ Response structure compatibility
- ✅ Logging and monitoring

### Environment Variables
- `TOPIC_ARN`: SNS topic for fraud alerts
- `REGION_NAME`: AWS region for service calls

The function maintains full compatibility with the Bedrock agent framework while providing financial fraud-specific analysis and alerting capabilities.