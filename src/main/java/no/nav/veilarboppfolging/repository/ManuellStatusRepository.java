package no.nav.veilarboppfolging.repository;

import lombok.SneakyThrows;
import no.nav.common.types.identer.AktorId;
import no.nav.veilarboppfolging.domain.KodeverkBruker;
import no.nav.veilarboppfolging.domain.ManuellStatus;
import no.nav.veilarboppfolging.utils.DbUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.ResultSet;
import java.util.List;
import java.util.Optional;

import static no.nav.veilarboppfolging.repository.OppfolgingsStatusRepository.AKTOR_ID;
import static no.nav.veilarboppfolging.repository.OppfolgingsStatusRepository.GJELDENDE_MANUELL_STATUS;
import static no.nav.veilarboppfolging.utils.DbUtils.hentZonedDateTime;
import static no.nav.veilarboppfolging.utils.DbUtils.queryForNullableObject;
import static no.nav.veilarboppfolging.utils.EnumUtils.getName;
import static no.nav.veilarboppfolging.utils.EnumUtils.valueOfOptional;
import static no.nav.veilarboppfolging.utils.ListUtils.firstOrNull;

@Repository
public class ManuellStatusRepository {

    private final JdbcTemplate db;

    private final TransactionTemplate transactor;

    @Autowired
    public ManuellStatusRepository(JdbcTemplate db, TransactionTemplate transactor) {
        this.db = db;
        this.transactor = transactor;
    }

    public void create(ManuellStatus manuellStatus) {
        transactor.executeWithoutResult((ignored) -> {
            manuellStatus.setId(DbUtils.nesteFraSekvens(db,"status_seq"));
            insert(manuellStatus);
            setActive(manuellStatus);
        });
    }

    public ManuellStatus fetch(Long id) {
        String sql = "SELECT * FROM MANUELL_STATUS WHERE id = ?";
        return firstOrNull(db.query(sql, ManuellStatusRepository::map, id));
    }

    public List<ManuellStatus> history(AktorId aktorId) {
        return db.query(
                "SELECT * FROM MANUELL_STATUS WHERE aktor_id = ?",
                ManuellStatusRepository::map,
                aktorId.get()
        );
    }

    public Optional<ManuellStatus> hentSisteManuellStatus(AktorId aktorId) {
        String sql = "SELECT * FROM MANUELL_STATUS WHERE aktor_id = ? ORDER BY OPPRETTET_DATO DESC FETCH NEXT 1 ROWS ONLY";
        return queryForNullableObject(db, sql, ManuellStatusRepository::map, aktorId.get());
    }

    @SneakyThrows
    public static ManuellStatus map(ResultSet result, int row) {
        return new ManuellStatus()
                .setId(result.getLong("id"))
                .setAktorId(result.getString("aktor_id"))
                .setManuell(result.getBoolean("manuell"))
                .setDato(hentZonedDateTime(result, "opprettet_dato"))
                .setBegrunnelse(result.getString("begrunnelse"))
                .setOpprettetAv(valueOfOptional(KodeverkBruker.class, result.getString("opprettet_av")).orElse(null))
                .setOpprettetAvBrukerId(result.getString("opprettet_av_brukerid"));
    }

    private void insert(ManuellStatus manuellStatus) {
        db.update(
                "INSERT INTO MANUELL_STATUS(" +
                        "id, " +
                        "aktor_id, " +
                        "manuell, " +
                        "opprettet_dato, " +
                        "begrunnelse, " +
                        "opprettet_av, " +
                        "opprettet_av_brukerid) " +
                        "VALUES(?, ?, ?, ?, ?, ?, ?)",
                manuellStatus.getId(),
                manuellStatus.getAktorId(),
                manuellStatus.isManuell(),
                manuellStatus.getDato(),
                manuellStatus.getBegrunnelse(),
                getName(manuellStatus.getOpprettetAv()),
                manuellStatus.getOpprettetAvBrukerId()
        );
    }

    private void setActive(ManuellStatus gjeldendeManuellStatus) {
        db.update("UPDATE " +
                        OppfolgingsStatusRepository.TABLE_NAME +
                        " SET " + GJELDENDE_MANUELL_STATUS + " = ?, " +
                        "oppdatert = CURRENT_TIMESTAMP, " +
                        "FEED_ID = null " +
                        "WHERE " + AKTOR_ID + " = ?",
                gjeldendeManuellStatus.getId(),
                gjeldendeManuellStatus.getAktorId()
        );
    }
}
