package com.amazonaws.proserve.workshop.process.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;
import lombok.extern.jackson.Jacksonized;

import java.time.Instant;

@Data
@Builder
@Jacksonized
public class FraudResult {
    @JsonProperty("attack_start_time")
    private Instant attackStartTime;
    @JsonProperty("attack_end_time")
    private Instant attackEndTime;
    @JsonProperty("attacker_id")
    private String attackerId;
    @JsonProperty("target_ip")
    private String targetIp;
    @JsonProperty("fragment_count")
    private Long fragmentCount;
    @JsonProperty("avg_packets")
    private Double avgPackets;
    @JsonProperty("avg_fragment_size")
    private Double avgFragmentSize;
    @JsonProperty("size_reduction_percent")
    private Double sizeReductionPercent;
    
    // Financial fraud specific fields
    @JsonProperty("fraud_type")
    private String fraudType;
    @JsonProperty("card_number")
    private String cardNumber;
    @JsonProperty("merchant_id")
    private String merchantId;
    @JsonProperty("device_id")
    private String deviceId;
    @JsonProperty("transaction_count")
    private Long transactionCount;
    @JsonProperty("total_amount")
    private Double totalAmount;
    @JsonProperty("avg_amount")
    private Double avgAmount;
    @JsonProperty("velocity_score")
    private Double velocityScore;
    @JsonProperty("locations")
    private String locations;
}