package no.nav.fo.veilarbsituasjon.db;

import no.nav.fo.veilarbsituasjon.IntegrasjonsTest;
import no.nav.fo.veilarbsituasjon.domain.Brukervilkar;
import no.nav.fo.veilarbsituasjon.domain.Situasjon;
import no.nav.fo.veilarbsituasjon.domain.VilkarStatus;
import org.junit.Before;
import org.junit.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.inject.Inject;

import java.sql.Timestamp;
import java.util.Optional;

import static java.lang.System.currentTimeMillis;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

public class SituasjonRepositoryTest extends IntegrasjonsTest {

    private static final String AKTOR_ID = "2222";

    @Inject
    private JdbcTemplate jdbcTemplate;

    private SituasjonRepository situasjonRepository;

    @Before
    public void setup() {
        situasjonRepository = new SituasjonRepository(jdbcTemplate);
    }

    @Test
    public void hentSituasjon_manglerSituasjon() throws Exception {
        sjekkAtSituasjonMangler(hentSituasjon("ukjentAktorId"));
        sjekkAtSituasjonMangler(hentSituasjon(null));
    }

    @Test
    public void oppdaterSituasjon_kanHenteSammeSituasjon() throws Exception {
        Situasjon situasjon = gittSituasjonForAktor(AKTOR_ID);
        Optional<Situasjon> uthentetSituasjon = hentSituasjon(AKTOR_ID);
        sjekkLikeSituasjoner(situasjon, uthentetSituasjon);
    }

    @Test
    public void oppdaterSituasjon_oppdatererStatus() throws Exception {
        Situasjon situasjon = gittSituasjonForAktor(AKTOR_ID);
        situasjon.leggTilBrukervilkar(new Brukervilkar()
                        .setDato(new Timestamp(currentTimeMillis()))
                        .setTekst("hash")
                        .setVilkarstatus(VilkarStatus.GODKJENNT)
        );
        situasjonRepository.oppdaterSituasjon(situasjon);
        Optional<Situasjon> uthentetSituasjon = hentSituasjon(AKTOR_ID);
        sjekkLikeSituasjoner(situasjon, uthentetSituasjon);
    }

    private void sjekkLikeSituasjoner(Situasjon oppdatertSituasjon, Optional<Situasjon> situasjon) {
        assertThat(oppdatertSituasjon, equalTo(situasjon.get()));
    }

    private Situasjon gittSituasjonForAktor(String aktorId) {
        Situasjon oppdatertSituasjon = new Situasjon().setAktorId(aktorId).setOppfolging(true);
        situasjonRepository.oppdaterSituasjon(oppdatertSituasjon);
        return oppdatertSituasjon;
    }

    private void sjekkAtSituasjonMangler(Optional<Situasjon> situasjon) {
        assertThat(situasjon.isPresent(), is(false));
    }

    private Optional<Situasjon> hentSituasjon(String ukjentAktorId) {
        return situasjonRepository.hentSituasjon(ukjentAktorId);
    }

}