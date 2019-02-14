package no.nav.fo.veilarboppfolging.services;

import net.javacrumbs.shedlock.core.LockingTaskExecutor;
import no.nav.dialogarena.aktor.AktorService;
import no.nav.fo.DatabaseTest;
import no.nav.fo.veilarboppfolging.db.OppfolgingsStatusRepository;
import no.nav.fo.veilarboppfolging.domain.IservMapper;
import no.nav.fo.veilarboppfolging.domain.OppfolgingTable;
import no.nav.fo.veilarboppfolging.mappers.ArenaBruker;
import org.junit.Before;
import org.junit.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.inject.Inject;
import java.time.ZonedDateTime;

import static java.time.ZonedDateTime.now;
import static java.util.Optional.of;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

public class Iserv28ServiceIntegrationTest extends DatabaseTest {

    private static int nesteAktorId;

    @Inject
    private JdbcTemplate jdbcTemplate;

    @Inject
    private LockingTaskExecutor taskExecutor;

    private Iserv28Service iserv28Service;

    private ZonedDateTime iservFraDato = now();
    private final static String AKTORID = "1234";

    private OppfolgingsStatusRepository oppfolgingStatusRepository = mock(OppfolgingsStatusRepository.class);

    private OppfolgingService oppfolgingService = mock(OppfolgingService.class);

    @Before
    public void setup() throws Exception {
        AktorService aktorService = mock(AktorService.class);
        when(aktorService.getFnr(anyString())).thenReturn(of("fnr"));
        when(oppfolgingStatusRepository.fetch(anyString())).thenReturn(new OppfolgingTable().setUnderOppfolging(true));
        when(oppfolgingService.avsluttOppfolgingForSystemBruker(anyString(), anyString(), anyString())).thenReturn(true);
        SystemUserSubjectProvider systemUserSubjectProvider = mock(SystemUserSubjectProvider.class);
        iserv28Service = new Iserv28Service(jdbcTemplate, oppfolgingService, oppfolgingStatusRepository, aktorService, taskExecutor, systemUserSubjectProvider);
    }

    @Test
    public void filterereOgInsertereIservBruker() {
        ArenaBruker arenaBruker = getArenaBruker();
        assertThat(iserv28Service.eksisterendeIservBruker(arenaBruker)).isNull();

        iserv28Service.filterereIservBrukere(arenaBruker);

        IservMapper iservMapper = iserv28Service.eksisterendeIservBruker(arenaBruker);
        assertThat(iservMapper).isNotNull();
        assertThat(iservMapper.getAktor_Id()).isEqualTo(AKTORID);
        assertThat(iservMapper.getIservSiden()).isEqualTo(iservFraDato);
    }

    @Test
    public void filterereOgOppdatereIservBruker(){
        ArenaBruker arenaBruker = getArenaBruker();
        iserv28Service.insertIservBruker(arenaBruker);
        assertThat(iserv28Service.eksisterendeIservBruker(arenaBruker)).isNotNull();

        arenaBruker.setIserv_fra_dato(arenaBruker.iserv_fra_dato.plusDays(2));
        iserv28Service.filterereIservBrukere(arenaBruker);

        IservMapper iservMapper = iserv28Service.eksisterendeIservBruker(arenaBruker);
        assertThat(iservMapper).isNotNull();
        assertThat(iservMapper.getAktor_Id()).isEqualTo(AKTORID);
        assertThat(iservMapper.getIservSiden()).isEqualTo(arenaBruker.getIserv_fra_dato());
    }

    @Test
    public void filterereOgSletteIservIkkeLengeBruker(){
        ArenaBruker arenaBruker = getArenaBruker();
        iserv28Service.insertIservBruker(arenaBruker);
        assertThat(iserv28Service.eksisterendeIservBruker(arenaBruker)).isNotNull();

        arenaBruker.setFormidlingsgruppekode("ARBS");
        iserv28Service.filterereIservBrukere(arenaBruker);
        assertThat(iserv28Service.eksisterendeIservBruker(arenaBruker)).isNull();
    }

    @Test
    public void finnBrukereMedIservI28Dager() {
        assertThat(iserv28Service.finnBrukereMedIservI28Dager()).isEmpty();

        insertIservBruker(now().minusDays(30));
        insertIservBruker(now().minusDays(27));
        insertIservBruker(now().minusDays(15));
        insertIservBruker(now());

        assertThat(iserv28Service.finnBrukereMedIservI28Dager()).hasSize(1);
    }

    @Test
    public void avsluttOppfolging(){
        ArenaBruker arenaBruker = insertIservBruker(iservFraDato);
        assertThat(iserv28Service.eksisterendeIservBruker(arenaBruker)).isNotNull();

        iserv28Service.avslutteOppfolging(arenaBruker.aktoerid);

        verify(oppfolgingService).avsluttOppfolgingForSystemBruker(anyString(), anyString(), anyString());
        assertThat(iserv28Service.eksisterendeIservBruker(arenaBruker)).isNull();
    }

    @Test
    public void automatiskAvslutteOppfolging_skalAvslutteBrukerSomErIserv28dagerOgUnderOppfolging(){
        ArenaBruker bruker = insertIservBruker(now().minusDays(30));

        iserv28Service.automatiskAvslutteOppfolging();

        assertThat(iserv28Service.eksisterendeIservBruker(bruker)).isNull();
    }

    @Test
    public void automatiskAvslutteOppfolging_skalFjerneBrukerSomErIserv28dagerOgIkkeUnderOppfolging(){
        ArenaBruker bruker = insertIservBruker(now().minusDays(30));
        when(oppfolgingStatusRepository.fetch(bruker.aktoerid)).thenReturn(new OppfolgingTable().setUnderOppfolging(false));

        iserv28Service.automatiskAvslutteOppfolging();

        verifyZeroInteractions(oppfolgingService);
        assertThat(iserv28Service.eksisterendeIservBruker(bruker)).isNull();
    }
    
    @Test
    public void automatiskAvslutteOppfolging_skalIkkeFjerneBrukerSomErIserv28dagerMenIkkeAvsluttet(){
        ArenaBruker bruker = insertIservBruker(now().minusDays(30));
        when(oppfolgingService.avsluttOppfolgingForSystemBruker(anyString(), anyString(), anyString())).thenReturn(false);

        iserv28Service.automatiskAvslutteOppfolging();

        assertThat(iserv28Service.eksisterendeIservBruker(bruker)).isNotNull();
    }
    
    private ArenaBruker getArenaBruker() {
        ArenaBruker arenaBruker = new ArenaBruker();
        arenaBruker.setAktoerid(AKTORID);
        arenaBruker.setFormidlingsgruppekode("ISERV");
        arenaBruker.setIserv_fra_dato(iservFraDato);
        return arenaBruker;
    }

    private ArenaBruker insertIservBruker(ZonedDateTime iservFraDato) {
        ArenaBruker arenaBruker = new ArenaBruker();
        arenaBruker.setAktoerid(Integer.toString(nesteAktorId++));
        arenaBruker.setFormidlingsgruppekode("ISERV");
        arenaBruker.setIserv_fra_dato(iservFraDato);
        arenaBruker.setFodselsnr("1111");

        assertThat(iserv28Service.eksisterendeIservBruker(arenaBruker)).isNull();
        iserv28Service.filterereIservBrukere(arenaBruker);
        return arenaBruker;
    }
}
