package no.nav.fo.veilarboppfolging.db;


import lombok.SneakyThrows;
import lombok.val;
import no.nav.fo.veilarboppfolging.domain.*;
import no.nav.sbl.jdbc.Database;
import org.springframework.transaction.annotation.Transactional;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import static java.util.Optional.ofNullable;
import static no.nav.apiapp.util.EnumUtils.getName;
import static no.nav.apiapp.util.EnumUtils.valueOfOptional;

public class OppfolgingRepository {

    private Database database;

    public OppfolgingRepository(Database database) {
        this.database = database;
    }

    public Optional<Oppfolging> hentOppfolging(String aktorId) {
        List<Oppfolging> oppfolging = database.query("" +
                        "SELECT" +
                        "  OPPFOLGINGSTATUS.aktor_id AS aktor_id, " +
                        "  OPPFOLGINGSTATUS.veileder AS veileder, " +
                        "  OPPFOLGINGSTATUS.under_oppfolging AS under_oppfolging, " +
                        "  OPPFOLGINGSTATUS.gjeldende_manuell_status AS gjeldende_manuell_status, " +
                        "  OPPFOLGINGSTATUS.gjeldende_eskaleringsvarsel AS gjeldende_eskaleringsvarsel, " +
                        "  OPPFOLGINGSTATUS.gjeldende_brukervilkar AS gjeldende_brukervilkar, " +
                        "  OPPFOLGINGSTATUS.gjeldende_mal AS gjeldende_mal, " +
                        "  MANUELL_STATUS.id AS ms_id, " +
                        "  MANUELL_STATUS.aktor_id AS ms_aktor_id, " +
                        "  MANUELL_STATUS.manuell AS ms_manuell, " +
                        "  MANUELL_STATUS.opprettet_dato AS ms_opprettet_dato, " +
                        "  MANUELL_STATUS.begrunnelse AS ms_begrunnelse, " +
                        "  MANUELL_STATUS.opprettet_av AS ms_opprettet_av, " +
                        "  MANUELL_STATUS.opprettet_av_brukerid AS ms_opprettet_av_brukerid, " +
                        "  BRUKERVILKAR.id AS brukervilkar_id, " +
                        "  BRUKERVILKAR.aktor_id AS brukervilkar_aktor_id, " +
                        "  BRUKERVILKAR.dato AS brukervilkar_dato, " +
                        "  BRUKERVILKAR.vilkarstatus AS brukervilkar_vilkarstatus, " +
                        "  BRUKERVILKAR.tekst AS brukervilkar_tekst, " +
                        "  BRUKERVILKAR.hash AS brukervilkar_hash, " +
                        "  MAL.id AS mal_id, " +
                        "  MAL.aktor_id AS mal_aktor_id, " +
                        "  MAL.mal AS mal_mal, " +
                        "  MAL.endret_av AS mal_endret_av, " +
                        "  MAL.dato AS mal_dato, " +
                        "  ESKALERINGSVARSEL.varsel_id AS esk_id, " +
                        "  ESKALERINGSVARSEL.aktor_id AS esk_aktor_id, " +
                        "  ESKALERINGSVARSEL.opprettet_av AS esk_opprettet_av, " +
                        "  ESKALERINGSVARSEL.opprettet_dato AS esk_opprettet_dato, " +
                        "  ESKALERINGSVARSEL.avsluttet_dato AS esk_avsluttet_dato, " +
                        "  ESKALERINGSVARSEL.avsluttet_begrunnelse AS esk_avsluttet_begrunnelse, " +
                        "  ESKALERINGSVARSEL.opprettet_begrunnelse AS esk_opprettet_begrunnelse, " +
                        "  ESKALERINGSVARSEL.avsluttet_av AS esk_avsluttet_av, " +
                        "  ESKALERINGSVARSEL.tilhorende_dialog_id AS esk_tilhorende_dialog_id " +
                        "FROM OPPFOLGINGSTATUS " +
                        "LEFT JOIN MANUELL_STATUS ON OPPFOLGINGSTATUS.gjeldende_manuell_status = MANUELL_STATUS.id " +
                        "LEFT JOIN BRUKERVILKAR ON OPPFOLGINGSTATUS.gjeldende_brukervilkar = BRUKERVILKAR.id " +
                        "LEFT JOIN MAL ON OPPFOLGINGSTATUS.gjeldende_mal = MAL.id " +
                        "LEFT JOIN ESKALERINGSVARSEL ON OPPFOLGINGSTATUS.gjeldende_eskaleringsvarsel = ESKALERINGSVARSEL.varsel_id " +
                        "WHERE OPPFOLGINGSTATUS.aktor_id = ? ",
                this::mapTilOppfolging,
                aktorId
        );

        return oppfolging.isEmpty() ? Optional.empty() : oppfolging.stream().findAny();
    }

    @Transactional
    public void startOppfolgingHvisIkkeAlleredeStartet(String aktorId) {
        if (!erOppfolgingsflaggSattForBruker(aktorId)) {
            database.update("UPDATE OPPFOLGINGSTATUS " +
                            "SET under_oppfolging = 1, " +
                            "oppdatert = CURRENT_TIMESTAMP " +
                            "WHERE aktor_id = ?",
                    aktorId);
            opprettOppfolgingsperiode(aktorId);
        }

    }

    private Boolean erOppfolgingsflaggSattForBruker(String aktorId) {
        return database.query("" +
                "SELECT " +
                "OPPFOLGINGSTATUS.under_oppfolging AS under_oppfolging " +
                "FROM OPPFOLGINGSTATUS " +
                "WHERE OPPFOLGINGSTATUS.aktor_id = ? ",
                this::erUnderOppfolging,
                aktorId
        ).get(0);
    }

    private Boolean erUnderOppfolging(ResultSet result) throws SQLException {
        return result.getBoolean("UNDER_OPPFOLGING");
    }

    @Transactional
    public void avsluttOppfolging(String aktorId, String veileder, String begrunnelse) {
        database.update("UPDATE OPPFOLGINGSTATUS SET under_oppfolging = 0, "
                + "veileder = null, "
                + "gjeldende_manuell_status = null, "
                + "gjeldende_mal = null, "
                + "gjeldende_brukervilkar = null, "
                + "oppdatert = CURRENT_TIMESTAMP "
                + "WHERE aktor_id = ?",
                aktorId
        );
        avsluttOppfolgingsperiode(aktorId, veileder, begrunnelse);
    }

    public void opprettStatus(Status status) {
        status.setId(nesteFraSekvens("status_seq"));
        oppdaterOppfolgingStatus(status);
        opprettOppfolgingStatus(status);
    }

    public void opprettBrukervilkar(Brukervilkar brukervilkar) {
        brukervilkar.setId(nesteFraSekvens("brukervilkar_seq"));
        opprettOppfolgingBrukervilkar(brukervilkar);
        oppdaterOppfolgingBrukervilkar(brukervilkar);
    }

    public void opprettMal(MalData mal) {
        mal.setId(nesteFraSekvens("MAL_SEQ"));
        oppdaterOppfolgingMal(mal);
        opprettOppfolgingMal(mal);
    }

    public Oppfolging opprettOppfolging(String aktorId) {
        database.update("INSERT INTO OPPFOLGINGSTATUS(" +
                        "aktor_id, " +
                        "under_oppfolging, " +
                        "oppdatert) " +
                        "VALUES(?, ?, CURRENT_TIMESTAMP)",
                aktorId,
                false);
        return new Oppfolging().setAktorId(aktorId).setUnderOppfolging(false);
    }

    public List<MalData> hentMalList(String aktorId) {
        return database.query("" +
                        "SELECT" +
                        "  id AS mal_id, " +
                        "  aktor_id AS mal_aktor_id, " +
                        "  mal AS mal_mal, " +
                        "  endret_av AS mal_endret_av, " +
                        "  dato AS mal_dato " +
                        "FROM MAL " +
                        "WHERE aktor_id = ? " +
                        "ORDER BY ID DESC",
                this::mapTilMal,
                aktorId);
    }

    public List<Brukervilkar> hentHistoriskeVilkar(String aktorId) {
        String sql =
                "SELECT " +
                "id AS brukervilkar_id, " +
                "aktor_id AS aktor_id, " +
                "dato AS brukervilkar_dato, " +
                "vilkarstatus AS brukervilkar_vilkarstatus, " +
                "tekst AS brukervilkar_tekst, " +
                "hash AS brukervilkar_hash " +
                "FROM BRUKERVILKAR " +
                "WHERE aktor_id = ? " +
                "ORDER BY dato DESC";
        return database.query(sql, this::mapTilBrukervilkar, aktorId);
    }

    private void avsluttOppfolgingsperiode(String aktorId, String veileder, String begrunnelse) {
        database.update("" +
                        "UPDATE OPPFOLGINGSPERIODE " +
                        "SET avslutt_veileder = ?, " +
                        "avslutt_begrunnelse = ?, " +
                        "sluttDato = CURRENT_TIMESTAMP, " +
                        "oppdatert = CURRENT_TIMESTAMP " +
                        "WHERE aktor_id = ? " +
                        "AND sluttDato IS NULL",
                veileder,
                begrunnelse,
                aktorId);
    }

    private void opprettOppfolgingsperiode(String aktorId) {
        database.update("" +
                        "INSERT INTO OPPFOLGINGSPERIODE(aktor_id, startDato, oppdatert) " +
                        "VALUES (?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
                aktorId);
    }

    public List<AvsluttetOppfolgingFeedData> hentAvsluttetOppfolgingEtterDato(Timestamp timestamp) {
        return database
                .query("SELECT aktor_id, sluttdato, oppdatert " +
                                "FROM OPPFOLGINGSPERIODE " +
                                "WHERE oppdatert >= ? and sluttdato is not null",
                        this::mapRadTilAvsluttetOppfolging,
                        timestamp);
    }

    @SneakyThrows
    private AvsluttetOppfolgingFeedData mapRadTilAvsluttetOppfolging(ResultSet rs) {
        return AvsluttetOppfolgingFeedData.builder()
                .aktoerid(rs.getString("aktor_id"))
                .sluttdato(rs.getTimestamp("sluttdato"))
                .oppdatert(rs.getTimestamp("oppdatert"))
                .build();
    }

    private void oppdaterOppfolgingBrukervilkar(Brukervilkar gjeldendeBrukervilkar) {
        database.update("UPDATE OPPFOLGINGSTATUS SET gjeldende_brukervilkar = ?, oppdatert = CURRENT_TIMESTAMP WHERE aktor_id = ?",
                gjeldendeBrukervilkar.getId(),
                gjeldendeBrukervilkar.getAktorId()
        );
    }

    private void oppdaterOppfolgingStatus(Status gjeldendeStatus) {
        database.update("UPDATE OPPFOLGINGSTATUS SET gjeldende_manuell_status = ?, oppdatert = CURRENT_TIMESTAMP WHERE aktor_id = ?",
                gjeldendeStatus.getId(),
                gjeldendeStatus.getAktorId()
        );
    }

    private void oppdaterOppfolgingMal(MalData mal) {
        database.update("UPDATE OPPFOLGINGSTATUS SET gjeldende_mal = ?, oppdatert = CURRENT_TIMESTAMP WHERE aktor_id = ?",
                mal.getId(),
                mal.getAktorId()
        );
    }

    private void opprettOppfolgingBrukervilkar(Brukervilkar vilkar) {
        database.update(
                "INSERT INTO BRUKERVILKAR(id, aktor_id, dato, vilkarstatus, tekst, hash) VALUES(?, ?, ?, ?, ?, ?)",
                vilkar.getId(),
                vilkar.getAktorId(),
                vilkar.getDato(),
                vilkar.getVilkarstatus().name(),
                vilkar.getTekst(),
                vilkar.getHash()

        );
    }

    private void opprettOppfolgingStatus(Status status) {
        database.update(
                "INSERT INTO MANUELL_STATUS(" +
                        "id, " +
                        "aktor_id, " +
                        "manuell, " +
                        "opprettet_dato, " +
                        "begrunnelse, " +
                        "opprettet_av, " +
                        "opprettet_av_brukerid) " +
                        "VALUES(?, ?, ?, ?, ?, ?, ?)",
                status.getId(),
                status.getAktorId(),
                status.isManuell(),
                status.getDato(),
                status.getBegrunnelse(),
                getName(status.getOpprettetAv()),
                status.getOpprettetAvBrukerId()
        );
    }

    public List<InnstillingsHistorikkData> hentManuellHistorikk(String aktorId) {
        return database.query(
                "SELECT manuell, opprettet_dato, begrunnelse, opprettet_av, opprettet_av_brukerid " +
                        "FROM MANUELL_STATUS " +
                        "WHERE aktor_id = ?",
                this::mapRadTilInnstillingsHistorikkData,
                aktorId);
    }

    private void opprettOppfolgingMal(MalData mal) {
        database.update(
                "INSERT INTO MAL(id, aktor_id, mal, endret_av, dato) " +
                        "VALUES(?, ?, ?, ?, ?)",
                mal.getId(),
                mal.getAktorId(),
                mal.getMal(),
                mal.getEndretAv(),
                mal.getDato()
        );
    }

    @Transactional
    public void slettMalForAktorEtter(String aktorId, Date date) {
        database.update("UPDATE OPPFOLGINGSTATUS SET gjeldende_mal = NULL WHERE aktor_id = ?", aktorId);
        database.update("DELETE FROM MAL WHERE aktor_id = ? AND dato > ?", aktorId, date);
    }

    private long nesteFraSekvens(String sekvensNavn) {
        return database.nesteFraSekvens(sekvensNavn);
    }

    private Oppfolging mapTilOppfolging(ResultSet resultat) throws SQLException {
        String aktorId = resultat.getString("aktor_id");
        return new Oppfolging()
                .setAktorId(aktorId)
                .setVeilederId(resultat.getString("veileder"))
                .setUnderOppfolging(resultat.getBoolean("under_oppfolging"))
                .setGjeldendeStatus(
                        Optional.ofNullable(resultat.getLong("gjeldende_manuell_status"))
                                .map(s -> s != 0 ? mapTilStatus(resultat) : null)
                                .orElse(null)
                )
                .setGjeldendeBrukervilkar(
                        Optional.ofNullable(resultat.getLong("gjeldende_brukervilkar"))
                                .map(b -> b != 0 ? mapTilBrukervilkar(resultat) : null)
                                .orElse(null)
                )
                .setGjeldendeMal(
                        Optional.ofNullable(resultat.getLong("gjeldende_mal"))
                                .map(m -> m != 0 ? mapTilMal(resultat) : null)
                                .orElse(null)
                )
                .setOppfolgingsperioder(hentOppfolgingsperioder(aktorId))
                .setGjeldendeEskaleringsvarsel(
                        Optional.ofNullable(resultat.getLong("gjeldende_eskaleringsvarsel"))
                                .map(e -> e != 0 ? mapTilEskaleringsvarselData(resultat) : null)
                                .orElse(null)
                );
    }


    private final static String hentOppfolingsperioderSQL =
            "SELECT aktor_id, avslutt_veileder, startdato, sluttdato, avslutt_begrunnelse " +
            "FROM OPPFOLGINGSPERIODE ";

    public List<Oppfolgingsperiode> hentOppfolgingsperioder(String aktorId) {
        return database.query(hentOppfolingsperioderSQL +
                        "WHERE aktor_id = ?",
                this::mapTilOppfolgingsperiode,
                aktorId
        );
    }

    public List<Oppfolgingsperiode> hentAvsluttetOppfolgingsperioder(String aktorId) {
        return database.query(hentOppfolingsperioderSQL +
                        "WHERE aktor_id = ? AND sluttdato is not null",
                this::mapTilOppfolgingsperiode,
                aktorId
        );
    }


    private EskaleringsvarselData hentEskaleringsvarsel(String aktorId) {
        List<EskaleringsvarselData> eskalering = database.query("" +
                "SELECT " +
                "varsel_id AS esk_id, " +
                "aktor_id AS esk_aktor_id, " +
                "opprettet_av AS esk_opprettet_av, " +
                "opprettet_dato AS esk_opprettet_dato, " +
                "avsluttet_dato AS esk_avsluttet_dato, " +
                "avsluttet_av AS esk_avsluttet_av, " +
                "tilhorende_dialog_id AS esk_tilhorende_dialog_id, " +
                "opprettet_begrunnelse AS esk_opprettet_begrunnelse, " +
                "avsluttet_begrunnelse AS esk_avsluttet_begrunnelse " +
                "FROM eskaleringsvarsel " +
                "WHERE varsel_id IN (SELECT gjeldende_eskaleringsvarsel FROM OPPFOLGINGSTATUS WHERE aktor_id = ?)",
                this::mapTilEskaleringsvarselData,
                aktorId
        );

        return eskalering.stream()
                .findAny()
                .orElse(null);

    }

    public List<EskaleringsvarselData> hentEskaleringhistorikk(String aktorId) {
        return database.query("SELECT " +
                        "varsel_id AS esk_id, " +
                        "aktor_id AS esk_aktor_id, " +
                        "opprettet_av AS esk_opprettet_av, " +
                        "opprettet_dato AS esk_opprettet_dato, " +
                        "avsluttet_av AS esk_avsluttet_av, " +
                        "avsluttet_dato AS esk_avsluttet_dato, " +
                        "tilhorende_dialog_id AS esk_tilhorende_dialog_id, " +
                        "avsluttet_begrunnelse AS esk_avsluttet_begrunnelse, " +
                        "opprettet_begrunnelse AS esk_opprettet_begrunnelse " +
                        "FROM eskaleringsvarsel " +
                        "WHERE aktor_id = ?",
                this::mapTilEskaleringsvarselData,
                aktorId
        );
    }

    @Transactional
    public void startEskalering(String aktorId, String opprettetAv, String opprettetBegrunnelse, long tilhorendeDialogId) {
        val harEksisterendeEskalering = hentEskaleringsvarsel(aktorId) != null;
        if (harEksisterendeEskalering) {
            throw new RuntimeException();
        }

        val id = nesteFraSekvens("ESKALERINGSVARSEL_SEQ");

        database.update("" +
                "INSERT INTO ESKALERINGSVARSEL(" +
                        "varsel_id, " +
                        "aktor_id, " +
                        "opprettet_av, " +
                        "opprettet_dato, " +
                        "opprettet_begrunnelse, " +
                        "tilhorende_dialog_id)" +
                "VALUES(?, ?, ?, CURRENT_TIMESTAMP, ?, ?)",
                id,
                aktorId,
                opprettetAv,
                opprettetBegrunnelse,
                tilhorendeDialogId
        );

        database.update("" +
                "UPDATE OPPFOLGINGSTATUS " +
                "SET gjeldende_eskaleringsvarsel = ?, " +
                "oppdatert = CURRENT_TIMESTAMP " +
                "WHERE aktor_id = ?",
                id,
                aktorId
        );
    }

    @Transactional
    public void stoppEskalering(String aktorId, String avsluttetAv, String avsluttetBegrunnelse) {
        val eskalering = hentEskaleringsvarsel(aktorId);
        val harIkkeEnEksisterendeEskalering = eskalering == null;
        if(harIkkeEnEksisterendeEskalering) {
            throw new RuntimeException();
        }

        database.update("" +
                "UPDATE ESKALERINGSVARSEL " +
                "SET avsluttet_dato = CURRENT_TIMESTAMP, avsluttet_begrunnelse = ?, avsluttet_av = ? " +
                "WHERE varsel_id = ?",
                avsluttetBegrunnelse,
                avsluttetAv,
                eskalering.getVarselId()
        );
        database.update("" +
                "UPDATE OPPFOLGINGSTATUS " +
                "SET gjeldende_eskaleringsvarsel = null, " +
                "oppdatert = CURRENT_TIMESTAMP " +
                "WHERE aktor_id = ?",
                aktorId
        );
    }

    @SneakyThrows
    private EskaleringsvarselData mapTilEskaleringsvarselData(ResultSet result) {
        return EskaleringsvarselData.builder()
                .varselId(result.getLong("esk_id"))
                .aktorId(result.getString("esk_aktor_id"))
                .opprettetAv(result.getString("esk_opprettet_av"))
                .opprettetDato(hentDato(result, "esk_opprettet_dato"))
                .opprettetBegrunnelse(result.getString("esk_opprettet_begrunnelse"))
                .avsluttetDato(hentDato(result, "esk_avsluttet_dato"))
                .avsluttetBegrunnelse(result.getString( "esk_avsluttet_begrunnelse"))
                .avsluttetAv(result.getString( "esk_avsluttet_av"))
                .tilhorendeDialogId(result.getLong("esk_tilhorende_dialog_id"))
                .build();
    }

    private Oppfolgingsperiode mapTilOppfolgingsperiode(ResultSet result) throws SQLException {
        return Oppfolgingsperiode.builder()
                .aktorId(result.getString("aktor_id"))
                .veileder(result.getString("avslutt_veileder"))
                .startDato(hentDato(result, "startdato"))
                .sluttDato(hentDato(result, "sluttdato"))
                .begrunnelse(result.getString("avslutt_begrunnelse"))
                .build();
    }

    private static Date hentDato(ResultSet rs, String kolonneNavn) throws SQLException {
        return ofNullable(rs.getTimestamp(kolonneNavn))
                .map(Timestamp::getTime)
                .map(Date::new)
                .orElse(null);
    }

    @SneakyThrows
    private Brukervilkar mapTilBrukervilkar(ResultSet result) {
        return new Brukervilkar(
                result.getString("aktor_id"),
                result.getTimestamp("brukervilkar_dato"),
                VilkarStatus.valueOf(result.getString("brukervilkar_vilkarstatus")),
                result.getString("brukervilkar_tekst"),
                result.getString("brukervilkar_hash")
        ).setId(result.getLong("brukervilkar_id"));
    }

    @SneakyThrows
    private Status mapTilStatus(ResultSet result) {
        return new Status(
                result.getString("aktor_id"),
                result.getBoolean("ms_manuell"),
                result.getTimestamp("ms_opprettet_dato"),
                result.getString("ms_begrunnelse"),
                valueOfOptional(KodeverkBruker.class, result.getString("ms_opprettet_av")).orElse(null),
                result.getString("ms_opprettet_av_brukerid")
        ).setId(result.getLong("ms_id"));
    }

    @SneakyThrows
    private MalData mapTilMal(ResultSet result) {
        return new MalData()
                .setId(result.getLong("mal_id"))
                .setAktorId(result.getString("mal_aktor_id"))
                .setMal(result.getString("mal_mal"))
                .setEndretAv(result.getString("mal_endret_av"))
                .setDato(result.getTimestamp("mal_dato"));
    }

    @SneakyThrows
    private InnstillingsHistorikkData mapRadTilInnstillingsHistorikkData(ResultSet result) {
        return new InnstillingsHistorikkData()
                .setManuell(result.getBoolean("manuell"))
                .setDato(result.getTimestamp("opprettet_dato"))
                .setBegrunnelse(result.getString("begrunnelse"))
                .setOpprettetAv(valueOfOptional(KodeverkBruker.class, result.getString("opprettet_av")).orElse(null))
                .setOpprettetAvBrukerId(result.getString("opprettet_av_brukerid"));

    }

}
