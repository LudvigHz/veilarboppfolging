package no.nav.veilarboppfolging.repository;

import lombok.SneakyThrows;
import no.nav.common.types.identer.AktorId;
import no.nav.veilarboppfolging.domain.EskaleringsvarselData;
import no.nav.veilarboppfolging.utils.DbUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.ResultSet;
import java.util.List;

import static no.nav.veilarboppfolging.repository.OppfolgingsStatusRepository.AKTOR_ID;
import static no.nav.veilarboppfolging.repository.OppfolgingsStatusRepository.GJELDENE_ESKALERINGSVARSEL;
import static no.nav.veilarboppfolging.utils.DbUtils.hentZonedDateTime;
import static no.nav.veilarboppfolging.utils.ListUtils.firstOrNull;

@Repository
public class EskaleringsvarselRepository {

    private final JdbcTemplate db;

    private final TransactionTemplate transactor;

    @Autowired
    public EskaleringsvarselRepository(JdbcTemplate db, TransactionTemplate transactor) {
        this.db = db;
        this.transactor = transactor;
    }

    public void create(EskaleringsvarselData e) {
        transactor.executeWithoutResult((ignored) -> {
            long id = DbUtils.nesteFraSekvens(db, "ESKALERINGSVARSEL_SEQ");
            EskaleringsvarselData varsel = e.withVarselId(id);
            insert(varsel);
            setActive(varsel);
        });
    }

    public EskaleringsvarselData fetch(Long id) {
        String sql = "SELECT * FROM ESKALERINGSVARSEL WHERE varsel_id = ?";
        return firstOrNull(db.query(sql, EskaleringsvarselRepository::map, id));
    }

    public void finish(AktorId aktorId, long varselId, String avsluttetAv, String avsluttetBegrunnelse) {
        transactor.executeWithoutResult((ignored) -> {
            avsluttEskaleringsVarsel(avsluttetBegrunnelse, avsluttetAv, varselId);
            removeActive(aktorId);
        });
    }


    public List<EskaleringsvarselData> history(AktorId aktorId) {
        return db.query("SELECT * FROM ESKALERINGSVARSEL WHERE aktor_id = ?",
                EskaleringsvarselRepository::map,
                aktorId.get());
    }

    @SneakyThrows
    private static EskaleringsvarselData map(ResultSet result, int row) {
        return EskaleringsvarselData.builder()
                .varselId(result.getLong("varsel_id"))
                .aktorId(result.getString("aktor_id"))
                .opprettetAv(result.getString("opprettet_av"))
                .opprettetDato(hentZonedDateTime(result, "opprettet_dato"))
                .opprettetBegrunnelse(result.getString("opprettet_begrunnelse"))
                .avsluttetDato(hentZonedDateTime(result, "avsluttet_dato"))
                .avsluttetBegrunnelse(result.getString( "avsluttet_begrunnelse"))
                .avsluttetAv(result.getString( "avsluttet_av"))
                .tilhorendeDialogId(result.getLong("tilhorende_dialog_id"))
                .build();
    }

    private void insert(EskaleringsvarselData e) {
        String sql = "INSERT INTO ESKALERINGSVARSEL" +
                "(varsel_id, aktor_id, opprettet_av, opprettet_dato, opprettet_begrunnelse, tilhorende_dialog_id)" +
                " VALUES(?, ?, ?, CURRENT_TIMESTAMP, ?, ?)";

        db.update(sql, e.getVarselId(), e.getAktorId(), e.getOpprettetAv(), e.getOpprettetBegrunnelse(), e.getTilhorendeDialogId());
    }

    private void setActive(EskaleringsvarselData e) {
        db.update("" +
                        "UPDATE " + OppfolgingsStatusRepository.TABLE_NAME +
                        " SET " + GJELDENE_ESKALERINGSVARSEL + " = ?, " +
                        "oppdatert = CURRENT_TIMESTAMP, " +
                        "FEED_ID = null " +
                        "WHERE " + AKTOR_ID + " = ?",
                e.getVarselId(),
                e.getAktorId()
        );
    }

    void avsluttEskaleringsVarsel(String avsluttetBegrunnelse, String avsluttetAv, long varselId) {
        db.update("" +
                        "UPDATE ESKALERINGSVARSEL " +
                        "SET avsluttet_dato = CURRENT_TIMESTAMP, avsluttet_begrunnelse = ?, avsluttet_av = ? " +
                        "WHERE varsel_id = ?",
                avsluttetBegrunnelse,
                avsluttetAv,
                varselId);
    }

    private void removeActive(AktorId aktorId) {
        db.update("" +
                        "UPDATE " + OppfolgingsStatusRepository.TABLE_NAME +
                        " SET " + GJELDENE_ESKALERINGSVARSEL + " = null, " +
                        "oppdatert = CURRENT_TIMESTAMP, " +
                        "FEED_ID = null " +
                        "WHERE " + AKTOR_ID + " = ?",
                aktorId.get()
        );
    }
}
