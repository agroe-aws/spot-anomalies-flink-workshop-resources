package com.amazonaws.proserve.workshop;

import com.amazonaws.proserve.workshop.process.model.FinancialEvent;
import com.amazonaws.proserve.workshop.process.model.FraudResult;
import com.amazonaws.proserve.workshop.serde.JsonDeserializationSchema;
import com.amazonaws.proserve.workshop.serde.JsonSerializationSchema;
import com.amazonaws.services.kinesisanalytics.runtime.KinesisAnalyticsRuntime;

import lombok.extern.slf4j.Slf4j;

import org.apache.commons.lang3.StringUtils;
import org.apache.flink.cep.CEP;
import org.apache.flink.cep.PatternStream;
import org.apache.flink.cep.nfa.aftermatch.AfterMatchSkipStrategy;
import org.apache.flink.cep.pattern.Pattern;
import org.apache.flink.cep.pattern.conditions.SimpleCondition;
import org.apache.flink.streaming.api.windowing.time.Time;
import org.apache.flink.connector.kafka.sink.KafkaSink;
import org.apache.flink.connector.kafka.sink.KafkaRecordSerializationSchema;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.Set;
import java.util.HashSet;

import org.apache.flink.streaming.api.environment.StreamExecutionEnvironment;
import org.apache.flink.api.common.eventtime.WatermarkStrategy;
import org.apache.flink.connector.kafka.source.KafkaSource;
import org.apache.flink.connector.kafka.source.enumerator.initializer.OffsetsInitializer;
import org.apache.flink.streaming.api.datastream.*;
import picocli.CommandLine;

import java.io.IOException;
import java.util.Properties;

@CommandLine.Command(name = "FraudDetection", mixinStandardHelpOptions = true, description = "Detect fraudulent transaction patterns")
@Slf4j
public class FraudDetection implements Runnable {
    @CommandLine.Option(names = { "-g", "--config-group" }, description = "Configuration Group")
    private static String propertyGroupId = "FraudDetection";

    @CommandLine.Option(names = { "-f", "--config-file" }, description = "Configuration File")
    private static String propertyFile = "";

    public static void main(String[] args) {
        new CommandLine(new FraudDetection()).execute(args);
    }

    @Override
    public void run() {
        try {
            Properties jobProps = getProps(propertyGroupId, propertyFile);

            String sourceTopic = getProperty(jobProps, "sourceTopic", "");
            String sourceBootstrapServer = getProperty(jobProps, "sourceBootstrapServer", "");
            String sinkTopic = getProperty(jobProps, "sinkTopic", "");
            String sinkBootstrapServer = getProperty(jobProps, "sinkBootstrapServer", "");

            final StreamExecutionEnvironment env = StreamExecutionEnvironment.getExecutionEnvironment();
            
            if (env instanceof org.apache.flink.streaming.api.environment.LocalStreamEnvironment) {
                org.apache.flink.configuration.Configuration config = new org.apache.flink.configuration.Configuration();
                env.configure(config);
                env.setParallelism(6);
            }
            
            Properties kafkaProps = new Properties();
            kafkaProps.setProperty("security.protocol", "SASL_SSL");
            kafkaProps.setProperty("sasl.mechanism", "AWS_MSK_IAM");
            kafkaProps.setProperty("sasl.jaas.config", "software.amazon.msk.auth.iam.IAMLoginModule required;");
            kafkaProps.setProperty("sasl.client.callback.handler.class",
                    "software.amazon.msk.auth.iam.IAMClientCallbackHandler");

            String initpos = getProperty(jobProps, "initpos", "EARLIEST");
            OffsetsInitializer startingOffsets;
            if ("LATEST".equals(initpos)) {
                startingOffsets = OffsetsInitializer.latest();
            } else if ("EARLIEST".equals(initpos)) {
                startingOffsets = OffsetsInitializer.earliest();
            } else {
                startingOffsets = OffsetsInitializer.timestamp(Long.parseLong(initpos));
            }

            final KafkaSource<FinancialEvent> dataSource = KafkaSource.<FinancialEvent>builder()
                    .setProperties(kafkaProps)
                    .setBootstrapServers(sourceBootstrapServer)
                    .setGroupId("FraudDetectorApp")
                    .setTopics(sourceTopic)
                    .setStartingOffsets(startingOffsets)
                    .setValueOnlyDeserializer(JsonDeserializationSchema.forSpecific(FinancialEvent.class))
                    .build();

            final DataStream<FinancialEvent> stream = env.fromSource(dataSource, 
                    WatermarkStrategy.<FinancialEvent>forMonotonousTimestamps()
                            .withTimestampAssigner((event, timestamp) -> event.getCalculatedEventTime().toEpochMilli()), 
                    "Source");
            
            // Card Testing Pattern: Multiple small transactions from same device
            Pattern<FinancialEvent, ?> cardTestingPattern = Pattern.<FinancialEvent>begin("cardTesting", AfterMatchSkipStrategy.skipPastLastEvent())
                .where(SimpleCondition.of(event -> 
                    "PURCHASE".equals(event.getEventType()) && 
                    event.getAmount() != null && 
                    event.getAmount() < 5.0))
                .times(10, 50)
                .within(Time.minutes(5));

            // Velocity Fraud Pattern: Same card in multiple locations
            Pattern<FinancialEvent, ?> velocityPattern = Pattern.<FinancialEvent>begin("velocity", AfterMatchSkipStrategy.skipPastLastEvent())
                .where(SimpleCondition.of(event -> 
                    "PURCHASE".equals(event.getEventType()) && 
                    event.getAmount() != null && 
                    event.getAmount() > 20.0))
                .times(3, 10)
                .within(Time.hours(2));

            // Apply Card Testing CEP pattern
            PatternStream<FinancialEvent> cardTestingStream = CEP.pattern(
                    stream.keyBy(FinancialEvent::getDeviceId), cardTestingPattern)
                    .inProcessingTime();

            // Apply Velocity CEP pattern  
            PatternStream<FinancialEvent> velocityStream = CEP.pattern(
                    stream.keyBy(FinancialEvent::getCardNumber), velocityPattern)
                    .inProcessingTime();

            // Extract card testing results
            DataStream<FraudResult> cardTestingResults = cardTestingStream.select(
                    (Map<String, List<FinancialEvent>> pattern) -> {
                        List<FinancialEvent> events = pattern.get("cardTesting");
                        FinancialEvent first = events.get(0);
                        FinancialEvent last = events.get(events.size() - 1);
                        
                        Set<String> uniqueCards = events.stream()
                                .map(FinancialEvent::getCardNumber)
                                .collect(Collectors.toSet());
                        
                        double totalAmount = events.stream()
                                .mapToDouble(FinancialEvent::getAmount)
                                .sum();
                        
                        return FraudResult.builder()
                                .attackStartTime(first.getCalculatedEventTime())
                                .attackEndTime(Instant.ofEpochMilli(last.getTsEnd().longValue()))
                                .attackerId(first.getDeviceId())
                                .targetIp(first.getMerchantId())
                                .fragmentCount((long) events.size())
                                .avgPackets((double) events.size())
                                .avgFragmentSize(totalAmount / events.size())
                                .sizeReductionPercent(((double) uniqueCards.size() / events.size()) * 100)
                                .fraudType("CARD_TESTING")
                                .cardNumber(String.valueOf(uniqueCards.size()) + " cards")
                                .merchantId(first.getMerchantId())
                                .deviceId(first.getDeviceId())
                                .transactionCount((long) events.size())
                                .totalAmount(totalAmount)
                                .avgAmount(totalAmount / events.size())
                                .velocityScore((double) events.size() / 5.0)
                                .locations(first.getLocationCity())
                                .build();
                    });

            // Extract velocity fraud results
            DataStream<FraudResult> velocityResults = velocityStream.select(
                    (Map<String, List<FinancialEvent>> pattern) -> {
                        List<FinancialEvent> events = pattern.get("velocity");
                        FinancialEvent first = events.get(0);
                        FinancialEvent last = events.get(events.size() - 1);
                        
                        Set<String> uniqueLocations = events.stream()
                                .map(e -> e.getLocationCity() + "," + e.getLocationCountry())
                                .collect(Collectors.toSet());
                        
                        double totalAmount = events.stream()
                                .mapToDouble(FinancialEvent::getAmount)
                                .sum();
                        
                        return FraudResult.builder()
                                .attackStartTime(first.getCalculatedEventTime())
                                .attackEndTime(Instant.ofEpochMilli(last.getTsEnd().longValue()))
                                .attackerId(first.getCardNumber())
                                .targetIp(String.join(";", uniqueLocations))
                                .fragmentCount((long) events.size())
                                .avgPackets((double) uniqueLocations.size())
                                .avgFragmentSize(totalAmount / events.size())
                                .sizeReductionPercent(((double) uniqueLocations.size() / events.size()) * 100)
                                .fraudType("VELOCITY_FRAUD")
                                .cardNumber(first.getCardNumber())
                                .merchantId("Multiple")
                                .deviceId("Multiple")
                                .transactionCount((long) events.size())
                                .totalAmount(totalAmount)
                                .avgAmount(totalAmount / events.size())
                                .velocityScore((double) uniqueLocations.size() * 2.0)
                                .locations(String.join(";", uniqueLocations))
                                .build();
                    });

            // Union both fraud detection streams
            DataStream<FraudResult> allFraudResults = cardTestingResults.union(velocityResults);

            // Create Kafka sink
            KafkaSink<FraudResult> sink = KafkaSink.<FraudResult>builder()
                    .setBootstrapServers(sinkBootstrapServer)
                    .setRecordSerializer(KafkaRecordSerializationSchema.builder()
                            .setTopic(sinkTopic)
                            .setValueSerializationSchema(JsonSerializationSchema.forSpecific(FraudResult.class))
                            .build())
                    .setKafkaProducerConfig(kafkaProps)
                    .build();

            allFraudResults.sinkTo(sink).name("Sink");
            
            env.execute("Fraud Detection");
        } catch (Exception ex) {
            log.error("Failed to initialize job: {}", ex.getMessage(), ex);
            throw new RuntimeException(ex);
        }
    }

    protected static Properties getProps(String propertyGroupId, String configFile) throws IOException {
        if (!configFile.isEmpty()) {
            Properties props = new Properties();
            try (java.io.FileInputStream fis = new java.io.FileInputStream(configFile)) {
                props.load(fis);
            }
            return props;
        } else {
            Map<String, Properties> appConfigs = KinesisAnalyticsRuntime.getApplicationProperties();
            Properties props = appConfigs.get(propertyGroupId);
            if (props == null || props.isEmpty()) {
                throw new IllegalArgumentException("No such property group found: " + propertyGroupId);
            }
            return props;
        }
    }

    protected static String getProperty(Properties properties, String name, String defaultValue) {
        String value = properties.getProperty(name);
        if (StringUtils.isBlank(value)) {
            value = defaultValue;
        }
        return value;
    }
}