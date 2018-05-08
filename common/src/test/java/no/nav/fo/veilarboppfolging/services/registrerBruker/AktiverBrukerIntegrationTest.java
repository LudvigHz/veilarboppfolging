package no.nav.fo.veilarboppfolging.services.registrerBruker;

import io.vavr.control.Try;
import no.nav.apiapp.security.PepClient;
import no.nav.dialogarena.aktor.AktorService;
import no.nav.fo.veilarboppfolging.config.DatabaseConfig;
import no.nav.fo.veilarboppfolging.config.RemoteFeatureConfig;
import no.nav.fo.veilarboppfolging.db.NyeBrukereFeedRepository;
import no.nav.fo.veilarboppfolging.db.OppfolgingRepository;
import no.nav.fo.veilarboppfolging.db.OppfolgingsPeriodeRepository;
import no.nav.fo.veilarboppfolging.domain.AktiverArbeidssokerData;
import no.nav.fo.veilarboppfolging.domain.Fnr;
import no.nav.fo.veilarboppfolging.domain.Oppfolging;
import no.nav.fo.veilarboppfolging.services.AktiverBrukerService;
import no.nav.sbl.jdbc.Database;
import no.nav.tjeneste.virksomhet.behandlearbeidssoeker.v1.binding.BehandleArbeidssoekerV1;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.jndi.SimpleNamingContextBuilder;

import java.util.Optional;

import static no.nav.fo.veilarboppfolging.config.DatabaseConfig.DATA_SOURCE_JDNI_NAME;
import static no.nav.fo.veilarboppfolging.config.JndiLocalContextConfig.setupInMemoryDatabase;
import static org.assertj.core.api.Java6Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class AktiverBrukerIntegrationTest {

    private static AnnotationConfigApplicationContext context;

    private static OppfolgingRepository oppfolgingRepository;
    private static OppfolgingsPeriodeRepository oppfolgingsPeriodeRepository;
    private static AktorService aktorService;
    private static BehandleArbeidssoekerV1 behandleArbeidssoekerV1;
    private static RemoteFeatureConfig.OpprettBrukerIArenaFeature opprettBrukerIArenaFeature;
    private static RemoteFeatureConfig.RegistreringFeature registreringFeature;
    private static AktiverBrukerService aktiverBrukerService;
    private static String ident = "***REMOVED***";

    @BeforeEach
    public void setup() throws Exception {

        SimpleNamingContextBuilder builder = new SimpleNamingContextBuilder();
        builder.bind(DATA_SOURCE_JDNI_NAME, setupInMemoryDatabase());
        builder.activate();

        context = new AnnotationConfigApplicationContext(
                DatabaseConfig.class,
                BrukerregistreringConfigTest.class
        );

        context.start();

        aktiverBrukerService = context.getBean(AktiverBrukerService.class);
        oppfolgingRepository = context.getBean(OppfolgingRepository.class);
        oppfolgingsPeriodeRepository = context.getBean(OppfolgingsPeriodeRepository.class);
        aktorService = context.getBean(AktorService.class);
        behandleArbeidssoekerV1 = context.getBean(BehandleArbeidssoekerV1.class);
        opprettBrukerIArenaFeature = context.getBean(RemoteFeatureConfig.OpprettBrukerIArenaFeature.class);
        registreringFeature = context.getBean(RemoteFeatureConfig.RegistreringFeature.class);
    }

    @AfterEach
    public void tearDown() {
        context.stop();
    }

    @Test
    public void skalRulleTilbakeDatabaseDersomKallTilArenaFeiler() throws Exception {
        cofigureMocks();
        doThrow(new RuntimeException()).when(behandleArbeidssoekerV1).aktiverBruker(any());

        AktiverArbeidssokerData data = lagBruker(ident);

        Try<Void> run = Try.run(() -> aktiverBrukerService.aktiverBruker(data));
        assertThat(run.isFailure()).isTrue();

        Optional<Oppfolging> oppfolging = oppfolgingRepository.hentOppfolging(ident);

        assertThat(oppfolging.isPresent()).isFalse();
    }

    @Test
    public void skalLagreIDatabaseDersomKallTilArenaErOK() throws Exception {
        cofigureMocks();

        aktiverBrukerService.aktiverBruker(lagBruker(ident));

        Optional<Oppfolging> oppfolging = oppfolgingRepository.hentOppfolging(ident);

        assertThat(oppfolging.isPresent()).isTrue();
    }

    @Test
    public void skalHaandtereAtOppfolgingstatusAlleredeFinnes() {
        cofigureMocks();
        oppfolgingRepository.opprettOppfolging(ident);
        oppfolgingsPeriodeRepository.avslutt(ident, "veilederid", "begrunnelse" );

        aktiverBrukerService.aktiverBruker(lagBruker(ident));

        Optional<Oppfolging> oppfolging = oppfolgingRepository.hentOppfolging(ident);

        assertThat(oppfolging.get().isUnderOppfolging()).isTrue();
    }

    private void cofigureMocks() {
        when(registreringFeature.erAktiv()).thenReturn(true);
        when(opprettBrukerIArenaFeature.erAktiv()).thenReturn(true);
        when(aktorService.getAktorId(any())).thenReturn(Optional.of(ident));
    }

    private AktiverArbeidssokerData lagBruker(String ident) {
        return new AktiverArbeidssokerData(new Fnr(ident), true);
    }

    @Configuration
    @ComponentScan
    public static class BrukerregistreringConfigTest {
        @Bean
        public OppfolgingRepository oppfolgingRepository(Database database) {
            return new OppfolgingRepository(database);
        }

        @Bean
        public OppfolgingsPeriodeRepository oppfolgingsPeriodeRepository(Database database) {
            return new OppfolgingsPeriodeRepository(database);
        }

        @Bean
        public AktorService aktoerService() {
            return mock(AktorService.class);
        }


        @Bean
        public BehandleArbeidssoekerV1 behandleArbeidssoekerV1() {
            return mock(BehandleArbeidssoekerV1.class);
        }

        @Bean
        public RemoteFeatureConfig.OpprettBrukerIArenaFeature opprettBrukerIArenaFeature() {
            return mock(RemoteFeatureConfig.OpprettBrukerIArenaFeature.class);
        }

        @Bean
        public RemoteFeatureConfig.RegistreringFeature registreringFeature() {
            return mock(RemoteFeatureConfig.RegistreringFeature.class);
        }

        @Bean
        public NyeBrukereFeedRepository nyeBrukereFeedRepository(Database database) {
            return new NyeBrukereFeedRepository(database);
        }

        @Bean
        AktiverBrukerService aktiverBrukerService(
                AktorService aktorService,
                BehandleArbeidssoekerV1 behandleArbeidssoekerV1,
                RemoteFeatureConfig.OpprettBrukerIArenaFeature sjekkRegistrereBrukerArenaFeature,
                RemoteFeatureConfig.RegistreringFeature skalRegistrereBrukerGenerellFeature,
                OppfolgingRepository oppfolgingRepository,
                NyeBrukereFeedRepository nyeBrukereFeedRepository,
                PepClient pepClient)
        {
            return new AktiverBrukerService(
                    oppfolgingRepository,
                    aktorService,
                    behandleArbeidssoekerV1,
                    sjekkRegistrereBrukerArenaFeature,
                    skalRegistrereBrukerGenerellFeature,
                    nyeBrukereFeedRepository,
                    pepClient
            );
        }

        @Bean
        PepClient pepClient() {
            return mock(PepClient.class);
        }
    }


}