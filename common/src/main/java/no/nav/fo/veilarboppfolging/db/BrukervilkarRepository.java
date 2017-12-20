package no.nav.fo.veilarboppfolging.db;

import lombok.SneakyThrows;
import no.nav.fo.veilarboppfolging.domain.Brukervilkar;
import no.nav.fo.veilarboppfolging.domain.VilkarStatus;
import no.nav.sbl.jdbc.Database;

import java.sql.ResultSet;
import java.util.List;

public class BrukervilkarRepository {
    private Database database;

    public BrukervilkarRepository(Database database) {
        this.database = database;
    }

    protected void create(Brukervilkar vilkar) {
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

    public List<Brukervilkar> history(String aktorId) {
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
        return database.query(sql, BrukervilkarRepository::map, aktorId);
    }

    @SneakyThrows
    public static Brukervilkar map(ResultSet result) {
        return new Brukervilkar(
                result.getString("aktor_id"),
                result.getTimestamp("brukervilkar_dato"),
                VilkarStatus.valueOf(result.getString("brukervilkar_vilkarstatus")),
                result.getString("brukervilkar_tekst"),
                result.getString("brukervilkar_hash")
        ).setId(result.getLong("brukervilkar_id"));
    }
}
