package no.nav.veilarboppfolging.config;

import io.confluent.kafka.serializers.AbstractKafkaSchemaSerDeConfig;
import io.confluent.kafka.serializers.KafkaAvroSerializer;
import net.javacrumbs.shedlock.core.LockProvider;
import no.nav.common.job.leader_election.LeaderElectionClient;
import no.nav.common.kafka.consumer.KafkaConsumerClient;
import no.nav.common.kafka.consumer.feilhandtering.KafkaConsumerRecordProcessor;
import no.nav.common.kafka.consumer.feilhandtering.KafkaConsumerRepository;
import no.nav.common.kafka.consumer.feilhandtering.util.KafkaConsumerRecordProcessorBuilder;
import no.nav.common.kafka.consumer.util.KafkaConsumerClientBuilder;
import no.nav.common.kafka.consumer.util.deserializer.Deserializers;
import no.nav.common.kafka.producer.KafkaProducerClient;
import no.nav.common.kafka.producer.feilhandtering.KafkaProducerRecordProcessor;
import no.nav.common.kafka.producer.feilhandtering.KafkaProducerRecordStorage;
import no.nav.common.kafka.producer.feilhandtering.KafkaProducerRepository;
import no.nav.common.kafka.producer.util.KafkaProducerClientBuilder;
import no.nav.common.kafka.spring.OracleJdbcTemplateConsumerRepository;
import no.nav.common.kafka.spring.OracleJdbcTemplateProducerRepository;
import no.nav.common.kafka.util.KafkaPropertiesBuilder;
import no.nav.common.utils.EnvironmentUtils;
import no.nav.paw.arbeidssokerregisteret.api.v1.Periode;
import no.nav.pto_schema.kafka.json.topic.onprem.EndringPaaOppfoelgingsBrukerV2;
import no.nav.veilarboppfolging.kafka.ArbeidssøkerperiodeConsumer;
import no.nav.veilarboppfolging.service.KafkaConsumerService;
import org.apache.kafka.clients.CommonClientConfigs;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.ByteArrayDeserializer;
import org.apache.kafka.common.serialization.ByteArraySerializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.kafka.test.EmbeddedKafkaBroker;

import jakarta.annotation.PostConstruct;
import org.springframework.kafka.test.context.EmbeddedKafka;

import java.util.List;
import java.util.Properties;
import java.util.UUID;

import static no.nav.common.kafka.consumer.util.ConsumerUtils.findConsumerConfigsWithStoreOnFailure;
import static no.nav.veilarboppfolging.config.KafkaConfig.CONSUMER_GROUP_ID;
import static no.nav.veilarboppfolging.config.KafkaConfig.PRODUCER_CLIENT_ID;

@Configuration
@EmbeddedKafka(
        partitions = 1
)
@EnableConfigurationProperties({KafkaProperties.class})
public class KafkaTestConfig {

    private final KafkaConsumerClient consumerClient;
    private final KafkaProducerClient producerClient;

    private final KafkaConsumerRecordProcessor consumerRecordProcessor;

    private final KafkaProducerRecordProcessor producerRecordProcessor;

    private final KafkaProducerRecordStorage producerRecordStorage;

    public KafkaTestConfig(
            LeaderElectionClient leaderElectionClient,
            JdbcTemplate jdbcTemplate,
            LockProvider lockProvider,
            KafkaConsumerService kafkaConsumerService,
            KafkaProperties kafkaProperties,
            EmbeddedKafkaBroker kafkaContainer,
            ArbeidssøkerperiodeConsumer arbeidssøkerperiodeConsumer
    ) {
        KafkaConsumerRepository consumerRepository = new OracleJdbcTemplateConsumerRepository(jdbcTemplate);
        KafkaProducerRepository producerRepository = new OracleJdbcTemplateProducerRepository(jdbcTemplate);
        EnvironmentUtils.setProperty("KAFKA_SCHEMA_REGISTRY","mock://testUrl", EnvironmentUtils.Type.PUBLIC);
        EnvironmentUtils.setProperty("KAFKA_SCHEMA_REGISTRY_USER","user", EnvironmentUtils.Type.PUBLIC);
        EnvironmentUtils.setProperty("KAFKA_SCHEMA_REGISTRY_PASSWORD","user", EnvironmentUtils.Type.PUBLIC);


        List<KafkaConsumerClientBuilder.TopicConfig<?, ?>> topicConfigs = List.of(
                new KafkaConsumerClientBuilder.TopicConfig<String, EndringPaaOppfoelgingsBrukerV2>()
                        .withLogging()
                        .withStoreOnFailure(consumerRepository)
                        .withConsumerConfig(
                                kafkaProperties.getEndringPaaOppfolgingBrukerTopic(),
                                Deserializers.stringDeserializer(),
                                Deserializers.jsonDeserializer(EndringPaaOppfoelgingsBrukerV2.class),
                                kafkaConsumerService::consumeEndringPaOppfolgingBruker
                        ),
                new KafkaConsumerClientBuilder.TopicConfig<String, Periode>()
                        .withLogging()
                        .withStoreOnFailure(consumerRepository)
                        .withConsumerConfig(
                                kafkaProperties.getArbeidssokerperioderTopicAiven(),
                                Deserializers.stringDeserializer(),
                                Deserializers.aivenAvroDeserializer(),
                                arbeidssøkerperiodeConsumer::consumeArbeidssøkerperiode
                        )
        );

        Properties consumerClientProperties = KafkaPropertiesBuilder.consumerBuilder()
                .withBaseProperties(1000)
                .withConsumerGroupId(CONSUMER_GROUP_ID)
                .withBrokerUrl(kafkaContainer.getBrokersAsString())
                .withDeserializers(ByteArrayDeserializer.class, ByteArrayDeserializer.class)
                .build();

        consumerClient = KafkaConsumerClientBuilder.builder()
                .withProperties(consumerClientProperties)
                .withTopicConfigs(topicConfigs)
                .build();

        consumerRecordProcessor = KafkaConsumerRecordProcessorBuilder
                .builder()
                .withLockProvider(lockProvider)
                .withKafkaConsumerRepository(consumerRepository)
                .withConsumerConfigs(findConsumerConfigsWithStoreOnFailure(topicConfigs))
                .build();

        Properties producerClientProperties = new Properties();
        producerClientProperties.put(CommonClientConfigs.BOOTSTRAP_SERVERS_CONFIG, kafkaContainer.getBrokersAsString());
        producerClientProperties.put(ProducerConfig.ACKS_CONFIG, "1");
        producerClientProperties.put(ProducerConfig.CLIENT_ID_CONFIG, UUID.randomUUID().toString());
        producerClientProperties.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        producerClientProperties.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, KafkaAvroSerializer.class);
        producerClientProperties.put(AbstractKafkaSchemaSerDeConfig.SCHEMA_REGISTRY_URL_CONFIG, "mock://testUrl");
        producerClientProperties.put(ProducerConfig.MAX_BLOCK_MS_CONFIG, 2000);
        producerClientProperties.put(ProducerConfig.LINGER_MS_CONFIG, 100);

        producerClient = KafkaProducerClientBuilder.builder()
                .withProperties(producerClientProperties)
                .build();

        producerRecordStorage = new KafkaProducerRecordStorage(producerRepository);

        KafkaProducerClient<byte[], byte[]> producerClient = KafkaProducerClientBuilder.<byte[], byte[]>builder()
                .withProperties(producerProperties(kafkaContainer))
                .build();

        producerRecordProcessor = new KafkaProducerRecordProcessor(producerRepository, producerClient, leaderElectionClient);
    }

    @Bean
    public KafkaProducerRecordStorage producerRecordStorage() {
        return producerRecordStorage;
    }

    private Properties producerProperties(EmbeddedKafkaBroker kafkaContainer) {
        return KafkaPropertiesBuilder.producerBuilder()
                .withBaseProperties()
                .withProducerId(PRODUCER_CLIENT_ID)
                .withBrokerUrl(kafkaContainer.getBrokersAsString())
                .withSerializers(ByteArraySerializer.class, ByteArraySerializer.class)
                .build();
    }

    @PostConstruct
    public void start() {
        consumerClient.start();
        consumerRecordProcessor.start();
        producerRecordProcessor.start();
    }
}
