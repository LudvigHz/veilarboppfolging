package no.nav.veilarboppfolging.kafka;

import lombok.extern.slf4j.Slf4j;
import no.nav.veilarboppfolging.domain.kafka.AvsluttOppfolgingKafkaDTO;
import no.nav.veilarboppfolging.repository.AvsluttOppfolgingEndringRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

import static no.nav.common.json.JsonUtils.toJson;

@Slf4j
@Component
public class AvsluttOppfolgingProducer {

    private final String topic;

    private final KafkaTemplate<String, String> kafkaTemplate;

    private final AvsluttOppfolgingEndringRepository avsluttOppfolgingEndringRepository;

    @Autowired
    public AvsluttOppfolgingProducer(KafkaTopics kafkaTopics, KafkaTemplate<String, String> kafkaTemplate, AvsluttOppfolgingEndringRepository avsluttOppfolgingEndringRepository) {
        topic = kafkaTopics.getEndringPaaAvsluttOppfolging();
        this.kafkaTemplate = kafkaTemplate;
        this.avsluttOppfolgingEndringRepository = avsluttOppfolgingEndringRepository;
    }

    public void avsluttOppfolgingEvent(String aktorId, LocalDateTime sluttdato) {
        final AvsluttOppfolgingKafkaDTO avsluttOppfolgingKafkaDTO = toDTO(aktorId, sluttdato);
        final String serialisertBruker = toJson(avsluttOppfolgingKafkaDTO);

        kafkaTemplate.send(topic, aktorId, serialisertBruker).addCallback(
                sendResult -> onSuccess(avsluttOppfolgingKafkaDTO),
                throwable -> onError(throwable, avsluttOppfolgingKafkaDTO)
        );
    }

    public void onSuccess(AvsluttOppfolgingKafkaDTO avsluttOppfolgingKafkaDTO) {
        avsluttOppfolgingEndringRepository.deleteAvsluttOppfolgingBruker(avsluttOppfolgingKafkaDTO.getAktorId(), avsluttOppfolgingKafkaDTO.getSluttdato());
        log.info("Bruker med aktorid {} har lagt på {}-topic", avsluttOppfolgingKafkaDTO, topic);
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void onError(Throwable throwable, AvsluttOppfolgingKafkaDTO avsluttOppfolgingKafkaDTO) {
        avsluttOppfolgingEndringRepository.insertAvsluttOppfolgingBruker(avsluttOppfolgingKafkaDTO.getAktorId(), avsluttOppfolgingKafkaDTO.getSluttdato());
        log.error("Kunne ikke publisere melding {} til {}-topic", avsluttOppfolgingKafkaDTO, topic, throwable);
    }

    public static AvsluttOppfolgingKafkaDTO toDTO(String aktorId, LocalDateTime sluttdato) {
        return new AvsluttOppfolgingKafkaDTO()
                .setAktorId(aktorId)
                .setSluttdato(sluttdato);
    }
}
