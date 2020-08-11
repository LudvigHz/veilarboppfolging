package no.nav.veilarboppfolging.service;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import no.nav.common.featuretoggle.UnleashService;
import no.nav.veilarboppfolging.client.veilarbarena.VeilarbArenaOppfolging;
import no.nav.veilarboppfolging.client.veilarbarena.VeilarbarenaClient;
import no.nav.veilarboppfolging.controller.domain.DkifResponse;
import no.nav.veilarboppfolging.controller.domain.UnderOppfolgingDTO;
import no.nav.veilarboppfolging.domain.*;
import no.nav.veilarboppfolging.kafka.AvsluttOppfolgingProducer;
import no.nav.veilarboppfolging.kafka.OppfolgingStatusKafkaProducer;
import no.nav.veilarboppfolging.repository.*;
import no.nav.veilarboppfolging.service.OppfolgingResolver.OppfolgingResolverDependencies;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static java.lang.Boolean.TRUE;
import static java.util.Optional.of;
import static java.util.Optional.ofNullable;
import static java.util.stream.Collectors.toList;
import static no.nav.veilarboppfolging.utils.ArenaUtils.*;
import static no.nav.veilarboppfolging.utils.KvpUtils.sjekkTilgangGittKvp;

@Slf4j
@Service
public class OppfolgingService {

    private final KvpService kvpService;
    private final MetricsService metricsService;
    private final ArenaOppfolgingService arenaOppfolgingService;
    private final AuthService authService;
    private final OppfolgingResolverDependencies oppfolgingResolverDependencies;
    private final OppfolgingsStatusRepository oppfolgingsStatusRepository;
    private final OppfolgingsPeriodeRepository oppfolgingsPeriodeRepository;
    private final ManuellStatusRepository manuellStatusRepository;
    private final ManuellStatusService manuellStatusService;
    private final VeilarbarenaClient veilarbarenaClient;
    private final UnleashService unleashService;
    private final OppfolgingStatusKafkaProducer kafkaProducer;
    private final EskaleringService eskaleringService;
    private final EskaleringsvarselRepository eskaleringsvarselRepository;
    private final KvpRepository kvpRepository;
    private final NyeBrukereFeedRepository nyeBrukereFeedRepository;
    private final MaalRepository maalRepository;
    private final AvsluttOppfolgingProducer avsluttOppfolgingProducer;

    @Autowired
    public OppfolgingService(
            KvpService kvpService,
            MetricsService metricsService,
            ArenaOppfolgingService arenaOppfolgingService,
            AuthService authService,
            OppfolgingResolverDependencies oppfolgingResolverDependencies,
            OppfolgingsStatusRepository oppfolgingsStatusRepository,
            OppfolgingsPeriodeRepository oppfolgingsPeriodeRepository,
            ManuellStatusRepository manuellStatusRepository,
            ManuellStatusService manuellStatusService,
            VeilarbarenaClient veilarbarenaClient,
            UnleashService unleashService,
            OppfolgingStatusKafkaProducer kafkaProducer,
            EskaleringService eskaleringService,
            EskaleringsvarselRepository eskaleringsvarselRepository,
            KvpRepository kvpRepository,
            NyeBrukereFeedRepository nyeBrukereFeedRepository,
            MaalRepository maalRepository,
            AvsluttOppfolgingProducer avsluttOppfolgingProducer) {
        this.kvpService = kvpService;
        this.metricsService = metricsService;
        this.arenaOppfolgingService = arenaOppfolgingService;
        this.authService = authService;
        this.oppfolgingResolverDependencies = oppfolgingResolverDependencies;
        this.oppfolgingsStatusRepository = oppfolgingsStatusRepository;
        this.oppfolgingsPeriodeRepository = oppfolgingsPeriodeRepository;
        this.manuellStatusRepository = manuellStatusRepository;
        this.manuellStatusService = manuellStatusService;
        this.veilarbarenaClient = veilarbarenaClient;
        this.unleashService = unleashService;
        this.kafkaProducer = kafkaProducer;
        this.eskaleringService = eskaleringService;
        this.eskaleringsvarselRepository = eskaleringsvarselRepository;
        this.kvpRepository = kvpRepository;
        this.nyeBrukereFeedRepository = nyeBrukereFeedRepository;
        this.maalRepository = maalRepository;
        this.avsluttOppfolgingProducer = avsluttOppfolgingProducer;
    }

    @Transactional
    public OppfolgingStatusData hentOppfolgingsStatus(String fnr) {
        authService.sjekkLesetilgangMedFnr(fnr);

        val resolver = OppfolgingResolver.lagOppfolgingResolver(fnr, oppfolgingResolverDependencies);

        resolver.sjekkStatusIArenaOgOppdaterOppfolging();




        return getOppfolgingStatusData(fnr, resolver);
    }

    public OppfolgingStatusData hentAvslutningStatus(String fnr) {
        authService.sjekkLesetilgangMedFnr(fnr);
        val resolver = OppfolgingResolver.lagOppfolgingResolver(fnr, oppfolgingResolverDependencies);
        return getOppfolgingStatusDataMedAvslutningStatus(fnr, resolver);
    }

    @SneakyThrows
    public OppfolgingStatusData startOppfolging(String fnr) {
        val resolver = sjekkTilgangTilEnhet(fnr);

        if (resolver.getKanSettesUnderOppfolging()) {
            resolver.startOppfolging();
        }

        kafkaProducer.send(new Fnr(fnr));

        return getOppfolgingStatusData(fnr, resolver);
    }

    @SneakyThrows
    @Transactional
    public OppfolgingStatusData avsluttOppfolging(String fnr, String veilederId, String begrunnelse) {
        val resolver = sjekkTilgangTilEnhet(fnr);

        resolver.avsluttOppfolging(veilederId, begrunnelse);
        resolver.reloadOppfolging();

        kafkaProducer.send(new Fnr(fnr));

        return getOppfolgingStatusDataMedAvslutningStatus(fnr, resolver);
    }

    @Transactional
    public boolean avsluttOppfolgingForSystemBruker(String fnr, String veileder, String begrunnelse) {
        /*
            TODO: Fjernet tilgangskontroll her siden det ikke gir mening å sjekke tilgang på en cron job.
                Gjør avklaring på at tilgangskontroll ikke trengs.
         */

        // TODO: Log
//        arenaOppfolgingTilstand().ifPresent(arenaStatus ->
//                log.info("Avslutting av oppfølging, tilstand i Arena for aktorid {}: {}", aktorId, arenaStatus));

        val resolver = OppfolgingResolver.lagOppfolgingResolver(fnr, oppfolgingResolverDependencies);
        return resolver.avsluttOppfolging(veileder, begrunnelse);
    }

    public List<AvsluttetOppfolgingFeedData> hentAvsluttetOppfolgingEtterDato(Timestamp timestamp, int pageSize) {
        return oppfolgingsPeriodeRepository.fetchAvsluttetEtterDato(timestamp, pageSize);
    }

    @SneakyThrows
    public VeilederTilgang hentVeilederTilgang(String fnr) {
        authService.sjekkLesetilgangMedFnr(fnr);

        if (unleashService.isEnabled("veilarboppfolging.hentVeilederTilgang.fra.veilarbarena")) {
            Optional<VeilarbArenaOppfolging> arenaBruker = veilarbarenaClient.hentOppfolgingsbruker(fnr);
            String oppfolgingsenhet = arenaBruker.map(VeilarbArenaOppfolging::getNav_kontor).orElse(null);
            boolean tilgangTilEnhet = authService.harTilgangTilEnhet(oppfolgingsenhet);
            return new VeilederTilgang().setTilgangTilBrukersKontor(tilgangTilEnhet);
        } else {
            val resolver = OppfolgingResolver.lagOppfolgingResolver(fnr, oppfolgingResolverDependencies);
            boolean tilgangTilEnhet = authService.harTilgangTilEnhet(resolver.getOppfolgingsEnhet());
            return new VeilederTilgang().setTilgangTilBrukersKontor(tilgangTilEnhet);
        }
    }

    public UnderOppfolgingDTO oppfolgingData(String fnr) {
        authService.sjekkLesetilgangMedFnr(fnr);

        return getOppfolgingStatus(fnr)
                .map(oppfolgingsstatus -> {
                    boolean isUnderOppfolging = oppfolgingsstatus.isUnderOppfolging();
                    return new UnderOppfolgingDTO().setUnderOppfolging(isUnderOppfolging).setErManuell(isUnderOppfolging && manuellStatusService.erManuell(oppfolgingsstatus));
                })
                .orElse(new UnderOppfolgingDTO().setUnderOppfolging(false).setErManuell(false));
    }

    public boolean underOppfolgingNiva3(String fnr) {
        String aktorId = authService.getAktorIdOrThrow(fnr);

        // TODO: Fjern denne
        authService.sjekkLesetilgangMedAktorId(aktorId);
        // TODO: Implementer sjekken under
        // pepClient.sjekkTilgangTilPerson(AbacPersonId.aktorId(aktorId.getAktorId()), ActionId.READ, ResourceType.VeilArbUnderOppfolging);

        return ofNullable(oppfolgingsStatusRepository.fetch(aktorId))
                .map(OppfolgingTable::isUnderOppfolging)
                .orElse(false);
    }

    private Optional<OppfolgingTable> getOppfolgingStatus(String fnr) {
        String aktorId = authService.getAktorIdOrThrow(fnr);
        authService.sjekkLesetilgangMedAktorId(aktorId);
        return ofNullable(oppfolgingsStatusRepository.fetch(aktorId));
    }

    private OppfolgingStatusData getOppfolgingStatusData(String fnr, OppfolgingResolver oppfolgingResolver) {
        return getOppfolgingStatusData(fnr, oppfolgingResolver, null);
    }

    private OppfolgingStatusData getOppfolgingStatusData(String fnr, OppfolgingResolver oppfolgingResolver, AvslutningStatusData avslutningStatusData) {
        Oppfolging oppfolging = oppfolgingResolver.getOppfolging();

        DkifResponse dkifResponse = oppfolgingResolver.reservertIKrr();
        boolean krr = dkifResponse.isKrr();
        boolean manuell = oppfolgingResolver.manuell();

        return new OppfolgingStatusData()
                .setFnr(fnr)
                .setAktorId(oppfolging.getAktorId())
                .setVeilederId(oppfolging.getVeilederId())
                .setUnderOppfolging(oppfolging.isUnderOppfolging())
                .setUnderKvp(oppfolging.getGjeldendeKvp() != null)
                .setReservasjonKRR(krr)
                .setManuell(manuell || krr)
                .setKanStarteOppfolging(oppfolgingResolver.getKanSettesUnderOppfolging())
                .setAvslutningStatusData(avslutningStatusData)
                .setGjeldendeEskaleringsvarsel(oppfolging.getGjeldendeEskaleringsvarsel())
                .setOppfolgingsperioder(oppfolging.getOppfolgingsperioder())
                .setHarSkriveTilgang(oppfolgingResolver.harSkrivetilgangTilBruker())
                .setInaktivIArena(oppfolgingResolver.getInaktivIArena())
                .setKanReaktiveres(oppfolgingResolver.getKanReaktiveres())
                .setErSykmeldtMedArbeidsgiver(oppfolgingResolver.getErSykmeldtMedArbeidsgiver())
                .setErIkkeArbeidssokerUtenOppfolging(oppfolgingResolver.getErSykmeldtMedArbeidsgiver())
                .setInaktiveringsdato(oppfolgingResolver.getInaktiveringsDato())
                .setServicegruppe(oppfolgingResolver.getServicegruppe())
                .setFormidlingsgruppe(oppfolgingResolver.getFormidlingsgruppe())
                .setRettighetsgruppe(oppfolgingResolver.getRettighetsgruppe())
                .setKanVarsles(!manuell && dkifResponse.isKanVarsles());
    }

    private OppfolgingStatusData getOppfolgingStatusDataMedAvslutningStatus(String fnr, OppfolgingResolver oppfolgingResolver) {
        val avslutningStatusData = AvslutningStatusData.builder()
                .kanAvslutte(oppfolgingResolver.kanAvslutteOppfolging())
                .underOppfolging(oppfolgingResolver.erUnderOppfolgingIArena())
                .harYtelser(oppfolgingResolver.harPagaendeYtelse())
                .harTiltak(oppfolgingResolver.harAktiveTiltak())
                .underKvp(oppfolgingResolverDependencies.getKvpService().erUnderKvp(authService.getAktorIdOrThrow(fnr)))
                .inaktiveringsDato(oppfolgingResolver.getInaktiveringsDato())
                .build();

        return getOppfolgingStatusData(fnr, oppfolgingResolver, avslutningStatusData);
    }


    @SneakyThrows
    public Optional<Oppfolging> hentOppfolging(String aktorId) {
        OppfolgingTable t = oppfolgingsStatusRepository.fetch(aktorId);

        if (t == null) {
            return Optional.empty();
        }

        Oppfolging o = new Oppfolging()
                .setAktorId(t.getAktorId())
                .setVeilederId(t.getVeilederId())
                .setUnderOppfolging(t.isUnderOppfolging());

        Kvp kvp = null;
        if (t.getGjeldendeKvpId() != 0) {
            kvp = kvpRepository.fetch(t.getGjeldendeKvpId());
            if (authService.harTilgangTilEnhet(kvp.getEnhet())) {
                o.setGjeldendeKvp(kvp);
            }
        }

        // Gjeldende eskaleringsvarsel inkluderes i resultatet kun hvis den innloggede veilederen har tilgang til brukers enhet.
        if (t.getGjeldendeEskaleringsvarselId() != 0) {
            EskaleringsvarselData varsel = eskaleringsvarselRepository.fetch(t.getGjeldendeEskaleringsvarselId());
            if (sjekkTilgangGittKvp(authService, kvp, varsel::getOpprettetDato)) {
                o.setGjeldendeEskaleringsvarsel(varsel);
            }
        }

        if (t.getGjeldendeMaalId() != 0) {
            o.setGjeldendeMal(maalRepository.fetch(t.getGjeldendeMaalId()));
        }

        if (t.getGjeldendeManuellStatusId() != 0) {
            o.setGjeldendeManuellStatus(manuellStatusRepository.fetch(t.getGjeldendeManuellStatusId()));
        }

        List<Kvp> kvpPerioder = kvpRepository.hentKvpHistorikk(aktorId);
        o.setOppfolgingsperioder(populerKvpPerioder(oppfolgingsPeriodeRepository.hentOppfolgingsperioder(t.getAktorId()), kvpPerioder));

        return Optional.of(o);
    }

    @Transactional
    public void startOppfolgingHvisIkkeAlleredeStartet(String aktorId) {
        startOppfolgingHvisIkkeAlleredeStartet(
                Oppfolgingsbruker.builder()
                        .aktoerId(aktorId)
                        .build()
        );
    }

    @Transactional
    public void startOppfolgingHvisIkkeAlleredeStartet(Oppfolgingsbruker oppfolgingsbruker) {
        String aktoerId = oppfolgingsbruker.getAktoerId();

        Oppfolging oppfolgingsstatus = hentOppfolging(aktoerId).orElseGet(() -> {
            // Siden det blir gjort mange kall samtidig til flere noder kan det oppstå en race condition
            // hvor oppfølging har blitt insertet av en annen node etter at den har sjekket at oppfølging
            // ikke ligger i databasen.
            try {
                return oppfolgingsStatusRepository.opprettOppfolging(aktoerId);
            } catch (DuplicateKeyException e) {
                log.info("Race condition oppstod under oppretting av ny oppfølging for bruker: " + aktoerId);
                return hentOppfolging(aktoerId).orElse(null);
            }
        });

        if (oppfolgingsstatus != null && !oppfolgingsstatus.isUnderOppfolging()) {
            oppfolgingsPeriodeRepository.start(aktoerId);
            nyeBrukereFeedRepository.leggTil(oppfolgingsbruker);
        }
    }

    @SneakyThrows
    private OppfolgingResolver sjekkTilgangTilEnhet(String fnr){
        authService.sjekkLesetilgangMedFnr(fnr);

        val resolver = OppfolgingResolver.lagOppfolgingResolver(fnr, oppfolgingResolverDependencies);

        if (!authService.harTilgangTilEnhet(resolver.getOppfolgingsEnhet())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }

        return resolver;
    }

    private List<Oppfolgingsperiode> populerKvpPerioder(List<Oppfolgingsperiode> oppfolgingsPerioder, List<Kvp> kvpPerioder) {
        return oppfolgingsPerioder.stream()
                .map(periode -> periode.toBuilder().kvpPerioder(
                        kvpPerioder.stream()
                                .filter(kvp -> erKvpIPeriode(kvp, periode))
                                .collect(toList())
                ).build())
                .collect(toList());
    }

    private boolean erKvpIPeriode(Kvp kvp, Oppfolgingsperiode periode) {
        return authService.harTilgangTilEnhet(kvp.getEnhet())
                && kvpEtterStartenAvPeriode(kvp, periode)
                && kvpForSluttenAvPeriode(kvp, periode);
    }

    private boolean kvpEtterStartenAvPeriode(Kvp kvp, Oppfolgingsperiode periode) {
        return !periode.getStartDato().after(kvp.getOpprettetDato());
    }

    private boolean kvpForSluttenAvPeriode(Kvp kvp, Oppfolgingsperiode periode) {
        return periode.getSluttDato() == null
                || !periode.getSluttDato().before(kvp.getOpprettetDato());
    }

    private void sjekkStatusIArenaOgOppdaterOppfolging(String fnr) {
        String aktorId = authService.getAktorIdOrThrow(fnr);
        Optional<ArenaOppfolgingTilstand> arenaOppfolgingTilstand = arenaOppfolgingService.hentOppfolgingTilstand(fnr);

        arenaOppfolgingTilstand.ifPresent((oppfolgingTilstand) -> {
            OppfolgingTable oppfolging = oppfolgingsStatusRepository.fetch(aktorId);

            boolean erUnderOppfolgingIArena = erUnderOppfolging(oppfolgingTilstand.getFormidlingsgruppe(), oppfolgingTilstand.getServicegruppe());

            if (!oppfolging.isUnderOppfolging() && erUnderOppfolgingIArena) {
                startOppfolgingHvisIkkeAlleredeStartet(aktorId);
            } else {
                boolean erSykmeldtMedArbeidsgiver = erSykmeldtMedArbeidsgiver(oppfolgingTilstand);
                boolean erInaktivIArena = erInaktivIArena(oppfolgingTilstand);
                boolean sjekkIArenaOmBrukerSkalAvsluttes = oppfolging.isUnderOppfolging() && erInaktivIArena;

                log.info("Statuser for reaktivering og inaktivering basert på {}: "
                                + "Aktiv Oppfølgingsperiode={} "
                                + "erSykmeldtMedArbeidsgiver={} "
                                + "inaktivIArena={} "
                                + "aktorId={} "
                                + "Tilstand i Arena: {}",
                        oppfolgingTilstand.isDirekteFraArena() ? "Arena" : "Veilarbarena",
                        oppfolging.isUnderOppfolging(),
                        erSykmeldtMedArbeidsgiver,
                        erInaktivIArena,
                        aktorId,
                        arenaOppfolgingTilstand.toString());

                if (sjekkIArenaOmBrukerSkalAvsluttes) {
                    sjekkOgOppdaterBrukerDirekteFraArena(fnr, oppfolgingTilstand, oppfolging);
                }
            }
        });
    }

    private void sjekkOgOppdaterBrukerDirekteFraArena(String fnr, ArenaOppfolgingTilstand arenaOppfolgingTilstand, OppfolgingTable oppfolging) {
        Optional<ArenaOppfolgingTilstand> maybeTilstandDirekteFraArena = arenaOppfolgingTilstand.isDirekteFraArena()
                ? of(arenaOppfolgingTilstand)
                : arenaOppfolgingService.hentOppfolgingTilstandDirekteFraArena(fnr);

        maybeTilstandDirekteFraArena.ifPresent(tilstandDirekteFraArena -> {
            boolean erInaktivIArena = erInaktivIArena(tilstandDirekteFraArena);
            boolean kanEnkeltReaktiveres = TRUE.equals(tilstandDirekteFraArena.getKanEnkeltReaktiveres());
            boolean skalAvsluttes = oppfolging.isUnderOppfolging() && erInaktivIArena && !kanEnkeltReaktiveres;

            log.info("Mulig avslutting av oppfølging "
                            + "erUnderOppfolging={} "
                            + "kanEnkeltReaktiveres={} "
                            + "inaktivIArena={} "
                            + "skalAvsluttes={} "
                            + "aktorId={} "
                            + "Tilstand i Arena: {}",
                    oppfolging.isUnderOppfolging(),
                    kanEnkeltReaktiveres,
                    erInaktivIArena,
                    skalAvsluttes,
                    oppfolging.getAktorId(),
                    arenaOppfolgingTilstand.toString());

            if (skalAvsluttes) {
                boolean kanAvslutte = kanAvslutteOppfolging();
                inaktiverBruker(oppfolging.isUnderOppfolging());
            }
        });
    }

    private void inaktiverBruker(String aktorId, boolean kanAvslutteOppfolging) {
        log.info("Avslutter oppfølgingsperiode for bruker");

        if (!kanAvslutteOppfolging) {
            avsluttOppfolgingForBruker(aktorId, null, "Oppfølging avsluttet automatisk pga. inaktiv bruker som ikke kan reaktiveres");
        } else {
            log.info("Avslutting av oppfølging ikke tillatt for aktorid {}", aktorId);
        }

        metricsService.raporterAutomatiskAvslutningAvOppfolging(!kanAvslutteOppfolging);
    }

    public boolean kanAvslutteOppfolging(String aktorId, boolean erUnderOppfolging, boolean erIservIArena) {
        boolean ikkeUnderKvp = !kvpService.erUnderKvp(aktorId);

        log.info("Kan oppfolging avsluttes for aktorid {}?, oppfolging.isUnderOppfolging(): {}, erIservIArena(): {}, !erUnderKvp(): {}",
                aktorId, erUnderOppfolging, erIservIArena, ikkeUnderKvp);

        return erUnderOppfolging
                && erIservIArena
                && ikkeUnderKvp;
    }

    private void avsluttOppfolgingForBruker(String aktorId, String veilederId, String begrunnelse) {
        try {
            // TODO: Sjekk om vi kan bruke veilederId istedenfor
            String brukerIdent = authService.getInnloggetBrukerIdent();
            eskaleringService.stoppEskalering(aktorId, brukerIdent, begrunnelse);
        } catch (Exception e) {
            log.warn("Klarte ikke å stoppe eskalering for bruker={} med veileder={}", aktorId, e);
        }

        oppfolgingsPeriodeRepository.avslutt(aktorId, veilederId, begrunnelse);
        avsluttOppfolgingProducer.avsluttOppfolgingEvent(aktorId, LocalDateTime.now());
    }

}
