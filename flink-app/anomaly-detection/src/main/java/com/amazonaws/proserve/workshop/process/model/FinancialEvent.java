/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */

package com.amazonaws.proserve.workshop.process.model;

import java.math.BigInteger;
import java.time.Instant;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;
import lombok.ToString;
import lombok.extern.jackson.Jacksonized;

@Data
@Builder
@Jacksonized
@ToString(exclude = { "text" })
public class FinancialEvent {
    @JsonProperty("event_type")
    private String eventType;
    @JsonProperty("transaction_id")
    private String transactionId;
    @JsonProperty("card_number")
    private String cardNumber;
    @JsonProperty("card_network")
    private String cardNetwork;
    @JsonProperty("amount")
    private Double amount;
    @JsonProperty("currency")
    private String currency;
    @JsonProperty("merchant_id")
    private String merchantId;
    @JsonProperty("merchant_name")
    private String merchantName;
    @JsonProperty("merchant_category_code")
    private String merchantCategoryCode;
    @JsonProperty("merchant_category_name")
    private String merchantCategoryName;
    @JsonProperty("device_id")
    private String deviceId;
    @JsonProperty("location_city")
    private String locationCity;
    @JsonProperty("location_state")
    private String locationState;
    @JsonProperty("location_country")
    private String locationCountry;
    @JsonProperty("timestamp_start")
    private BigInteger tsStart;
    @JsonProperty("timestamp_end")
    private BigInteger tsEnd;
    @JsonProperty("packets")
    private Integer packets;
    @JsonProperty("bytes")
    private Integer bytes;
    @JsonProperty("writer_id")
    private String writerId;
    @JsonProperty("text")
    private String text;
    
    public Instant getCalculatedEventTime() {
        return tsStart != null ? Instant.ofEpochMilli(tsStart.longValue()) : null;
    }
}