package no.nav.fo.veilarboppfolging.db;

import lombok.SneakyThrows;
import no.nav.fo.veilarboppfolging.domain.AvsluttOppfolgingKafkaDTO;
import no.nav.sbl.sql.SqlUtils;
import no.nav.sbl.sql.where.WhereClause;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import javax.inject.Inject;
import java.sql.ResultSet;
import java.util.Date;
import java.util.List;

@Component
public class AvsluttOppfolgingEndringRepository {
    private final static String KAFKA_TABLE = "KAFKA_AVSLUTT_OPPFOLGING";
    private final static String AKTOR_ID = "AKTOR_ID";
    private final static String SLUTTDATO = "SLUTTDATO";
    private JdbcTemplate db;

    @Inject
    public AvsluttOppfolgingEndringRepository(JdbcTemplate db) {
        this.db = db;
    }

    @Transactional
    public void insertAvsluttOppfolgingBruker(String aktorId) {
        SqlUtils.insert(db, KAFKA_TABLE)
                .value(AKTOR_ID, aktorId)
                .value(SLUTTDATO, new Date())
                .execute();
    }

    public void deleteAvsluttOppfolgingBruker(String aktorId) {
        SqlUtils.delete(db, KAFKA_TABLE)
                .where(WhereClause.equals(AKTOR_ID, aktorId))
                .execute();
    }

    public List<AvsluttOppfolgingKafkaDTO> hentAvsluttOppfolgingBrukere() {
        return SqlUtils.select(db, KAFKA_TABLE, AvsluttOppfolgingEndringRepository::avsluttOppfolgingKafkaDTOMapper)
                .column("*")
                .executeToList();
    }

    @SneakyThrows
    private static AvsluttOppfolgingKafkaDTO avsluttOppfolgingKafkaDTOMapper(ResultSet resultSet){
        Date sluttdato = new Date(resultSet.getTimestamp(SLUTTDATO).toInstant().toEpochMilli());
        return new AvsluttOppfolgingKafkaDTO()
                .setAktorId(resultSet.getString(AKTOR_ID))
                .setSluttdato(sluttdato);
    }
}
