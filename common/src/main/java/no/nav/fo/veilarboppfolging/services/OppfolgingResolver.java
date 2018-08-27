package no.nav.fo.veilarboppfolging.services;

import io.vavr.control.Try;
import lombok.Getter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import no.nav.apiapp.feil.UlovligHandling;
import no.nav.apiapp.security.PepClient;
import no.nav.brukerdialog.security.context.SubjectHandler;
import no.nav.dialogarena.aktor.AktorService;
import no.nav.fo.veilarbaktivitet.domain.arena.ArenaAktivitetDTO;
import no.nav.fo.veilarboppfolging.config.RemoteFeatureConfig;
import no.nav.fo.veilarboppfolging.db.KvpRepository;
import no.nav.fo.veilarboppfolging.db.OppfolgingRepository;
import no.nav.fo.veilarboppfolging.domain.*;
import no.nav.fo.veilarboppfolging.utils.FunksjonelleMetrikker;
import no.nav.fo.veilarboppfolging.utils.StringUtils;
import no.nav.fo.veilarboppfolging.vilkar.VilkarService;
import no.nav.metrics.MetricsFactory;
import no.nav.sbl.jdbc.Transactor;
import no.nav.tjeneste.virksomhet.digitalkontaktinformasjon.v1.DigitalKontaktinformasjonV1;
import no.nav.tjeneste.virksomhet.digitalkontaktinformasjon.v1.HentDigitalKontaktinformasjonKontaktinformasjonIkkeFunnet;
import no.nav.tjeneste.virksomhet.digitalkontaktinformasjon.v1.HentDigitalKontaktinformasjonPersonIkkeFunnet;
import no.nav.tjeneste.virksomhet.digitalkontaktinformasjon.v1.informasjon.WSKontaktinformasjon;
import no.nav.tjeneste.virksomhet.digitalkontaktinformasjon.v1.meldinger.WSHentDigitalKontaktinformasjonRequest;
import no.nav.tjeneste.virksomhet.digitalkontaktinformasjon.v1.meldinger.WSHentDigitalKontaktinformasjonResponse;
import no.nav.tjeneste.virksomhet.ytelseskontrakt.v3.YtelseskontraktV3;
import no.nav.tjeneste.virksomhet.ytelseskontrakt.v3.informasjon.ytelseskontrakt.WSYtelseskontrakt;
import no.nav.tjeneste.virksomhet.ytelseskontrakt.v3.meldinger.WSHentYtelseskontraktListeRequest;
import no.nav.tjeneste.virksomhet.ytelseskontrakt.v3.meldinger.WSHentYtelseskontraktListeResponse;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.stereotype.Component;

import javax.inject.Inject;
import java.sql.Timestamp;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static java.lang.System.currentTimeMillis;
import static java.util.Optional.of;
import static java.util.Optional.ofNullable;
import static no.nav.fo.veilarbaktivitet.domain.AktivitetStatus.AVBRUTT;
import static no.nav.fo.veilarbaktivitet.domain.AktivitetStatus.FULLFORT;
import static no.nav.fo.veilarboppfolging.domain.KodeverkBruker.SYSTEM;
import static no.nav.fo.veilarboppfolging.domain.VilkarStatus.GODKJENT;
import static no.nav.fo.veilarboppfolging.services.ArenaUtils.*;
import static no.nav.fo.veilarboppfolging.vilkar.VilkarService.VilkarType.PRIVAT;
import static no.nav.fo.veilarboppfolging.vilkar.VilkarService.VilkarType.UNDER_OPPFOLGING;

@Slf4j
public class OppfolgingResolver {

    private static final String AKTIV_YTELSE_STATUS = "Aktiv";

    private String fnr;
    private OppfolgingResolverDependencies deps;

    private String aktorId;
    private Oppfolging oppfolging;
    private Optional<ArenaOppfolging> statusIArena;
    private Boolean reservertIKrr;
    private WSHentYtelseskontraktListeResponse ytelser;
    private List<ArenaAktivitetDTO> arenaAktiviteter;
    private Boolean inaktivIArena;
    private Boolean kanReaktiveres;
    private Boolean erIkkeArbeidssokerUtenOppfolging;

    OppfolgingResolver(String fnr, OppfolgingResolverDependencies deps) {
        deps.getPepClient().sjekkLeseTilgangTilFnr(fnr);

        this.fnr = fnr;
        this.deps = deps;

        this.aktorId = deps.getAktorService().getAktorId(fnr)
                .orElseThrow(() -> new IllegalArgumentException("Fant ikke aktør for fnr: " + fnr));
        this.oppfolging = hentOppfolging();

        avsluttKvpVedEnhetBytte();
    }

    void reloadOppfolging() {
        oppfolging = hentOppfolging();
    }

    void sjekkStatusIArenaOgOppdaterOppfolging() {
        hentOppfolgingstatusFraArena();
        statusIArena.ifPresent((arenaStatus) -> {
            if (!oppfolging.isUnderOppfolging()) {
                if (erUnderOppfolging(arenaStatus.getFormidlingsgruppe(), arenaStatus.getServicegruppe(), arenaStatus.getHarMottaOppgaveIArena())) {
                    deps.getOppfolgingRepository().startOppfolgingHvisIkkeAlleredeStartet(aktorId);
                    reloadOppfolging();
                }

            }
            erIkkeArbeidssokerUtenOppfolging = erIARBSUtenOppfolging(
                    arenaStatus.getFormidlingsgruppe(),
                    arenaStatus.getServicegruppe()
                    );

            inaktivIArena = erIserv(statusIArena.get());
            kanReaktiveres = oppfolging.isUnderOppfolging() && kanReaktiveres(statusIArena.get());
            boolean skalAvsluttes = oppfolging.isUnderOppfolging() && inaktivIArena && !kanReaktiveres;
            log.info("Statuser for reaktivering og inaktivering: "
                    + "Aktiv Oppfølgingsperiode={} "
                    + "kanReaktiveres={} "
                    + "erIkkeArbeidssokerUtenOppfolging={} "
                    + "skalAvsluttes={} "
                    + "Tilstand i Arena: {}",
                    oppfolging.isUnderOppfolging(), kanReaktiveres, erIkkeArbeidssokerUtenOppfolging, skalAvsluttes, statusIArena.get());
            
            if(skalAvsluttes) {
                inaktiverBruker();
            }
        });
    }

    private void inaktiverBruker() {
        log.info("Avslutter oppfølgingsperiode for bruker");
        avsluttOppfolging(null, "Oppfølging avsluttet automatisk pga. inaktiv bruker som ikke kan reaktiveres");
        reloadOppfolging();
        MetricsFactory.createEvent("oppfolging.automatisk.avslutning").addFieldToReport("success", !oppfolging.isUnderOppfolging()).report();
    }

    void sjekkNyesteVilkarOgOppdaterOppfolging(String hash, VilkarStatus vilkarStatus) {
        Brukervilkar gjeldendeVilkar = getNyesteVilkar();
        if (gjeldendeVilkar.getHash().equals(hash)) {
            deps.getOppfolgingRepository().opprettBrukervilkar(
                    new Brukervilkar(
                            aktorId,
                            new Timestamp(currentTimeMillis()),
                            vilkarStatus,
                            gjeldendeVilkar.getTekst(),
                            hash
                    ));
        }
    }

    Brukervilkar getNyesteVilkar() {
        String vilkarTekst = deps.getVilkarService().getVilkar(oppfolging.isUnderOppfolging() ? UNDER_OPPFOLGING : PRIVAT, null);
        return new Brukervilkar()
                .setTekst(vilkarTekst)
                .setHash(DigestUtils.sha256Hex(vilkarTekst));
    }

    List<Brukervilkar> getHistoriskeVilkar() {
        return deps.getOppfolgingRepository().hentHistoriskeVilkar(aktorId);
    }

    boolean maVilkarBesvares() {
        if(deps.getBrukervilkarFeature().erAktiv() && oppfolging.isUnderOppfolging()) { //TODO: når featuretoggle slettes er det bare nødvending å sjekke på isUnderOppfolging og returnere false
            return false;
        }

        return ofNullable(oppfolging.getGjeldendeBrukervilkar())
                .filter(brukervilkar -> GODKJENT.equals(brukervilkar.getVilkarstatus()))
                .map(Brukervilkar::getHash)
                .map(brukerVilkar -> !brukerVilkar.equals(getNyesteVilkar().getHash()))
                .orElse(true);
    }

    List<MalData> getMalList() {
        return deps.getOppfolgingRepository().hentMalList(aktorId);
    }

    MalData oppdaterMal(String mal, String endretAv) {
        MalData malData = new MalData()
                .setAktorId(aktorId)
                .setMal(mal)
                .setEndretAv(StringUtils.of(endretAv).orElse(aktorId))
                .setDato(new Timestamp(currentTimeMillis()));
        deps.getOppfolgingRepository().opprettMal(malData);
        return hentOppfolging().getGjeldendeMal();
    }

    void slettMal() {
        // https://confluence.adeo.no/pages/viewpage.action?pageId=229941929
        Oppfolging oppfolging = getOppfolging();
        if (oppfolging.isUnderOppfolging()) {
            throw new UlovligHandling();
        } else {
            Date sisteSluttDatoEller1970 = oppfolging
                    .getOppfolgingsperioder()
                    .stream()
                    .map(Oppfolgingsperiode::getSluttDato)
                    .filter(Objects::nonNull)
                    .max(Date::compareTo)
                    .orElseGet(() -> new Date(0));
            deps.getOppfolgingRepository().slettMalForAktorEtter(aktorId, sisteSluttDatoEller1970);
        }
    }

    Oppfolging getOppfolging() {
        return oppfolging;
    }

    String getAktorId() {
        return aktorId;
    }

    boolean reservertIKrr() {
        if (reservertIKrr == null) {
            sjekkReservasjonIKrrOgOppdaterOppfolging();
        }
        return reservertIKrr;
    }

    boolean manuell() {
        return ofNullable(oppfolging.getGjeldendeManuellStatus())
                .map(ManuellStatus::isManuell)
                .orElse(false);
    }

    boolean getKanSettesUnderOppfolging() {
        if (oppfolging.isUnderOppfolging()) {
            return false;
        }
        if (statusIArena == null) {
            hentOppfolgingstatusFraArena();
        }
        return statusIArena.map(status ->
                kanSettesUnderOppfolging(status.getFormidlingsgruppe(),
                        status.getServicegruppe()))
                .orElse(false);
    }

    void startOppfolging() {
        deps.getOppfolgingRepository().startOppfolgingHvisIkkeAlleredeStartet(aktorId);
        oppfolging = hentOppfolging();
    }

    boolean erUnderOppfolgingIArena() {
        if (statusIArena == null) {
            hentOppfolgingstatusFraArena();
        }
        return statusIArena.map(status ->
                erUnderOppfolging(status.getFormidlingsgruppe(),
                        status.getServicegruppe(), status.getHarMottaOppgaveIArena()))
                .orElse(false);
    }

    boolean harPagaendeYtelse() {
        if (ytelser == null) {
            hentYtelseskontrakt();
        }
        return ytelser.getYtelseskontraktListe()
                .stream()
                .map(WSYtelseskontrakt::getStatus)
                .anyMatch(AKTIV_YTELSE_STATUS::equals);
    }

    boolean harAktiveTiltak() {
        if (arenaAktiviteter == null) {
            hentArenaAktiviteter();
        }
        return arenaAktiviteter
                .stream()
                .map(ArenaAktivitetDTO::getStatus)
                .anyMatch(status -> status != AVBRUTT && status != FULLFORT);
    }

    boolean erUnderKvp() {
        return deps.getKvpRepository().gjeldendeKvp(getAktorId()) != 0L;
    }

    boolean harSkrivetilgangTilBruker() {
        long kvpId = deps.getKvpRepository().gjeldendeKvp(getAktorId());
        return kvpId == 0L || tilgangTilEnhet(kvpId);
    }

    @SneakyThrows
    private boolean tilgangTilEnhet(long kvpId) {
        String enhet = deps.getKvpRepository().fetch(kvpId).getEnhet();
        return deps.getPepClient().harTilgangTilEnhet(enhet);
    }

    boolean kanAvslutteOppfolging() {
        return oppfolging.isUnderOppfolging()
                && !erUnderOppfolgingIArena()
                && !erUnderKvp();
    }

    Date getInaktiveringsDato() {
        if (statusIArena == null) {
            hentOppfolgingstatusFraArena();
        }
        
        return statusIArena.map(this::getInaktiveringsDato).orElse(null);
    }

    private Date getInaktiveringsDato(ArenaOppfolging status) {
        return Optional.ofNullable(status.getInaktiveringsdato()).isPresent()
                ? Date.from(status.getInaktiveringsdato().atStartOfDay().atZone(ZoneId.systemDefault()).toInstant())
                : null;
    }

    String getOppfolgingsEnhet() {
        if (statusIArena == null) {
            hentOppfolgingstatusFraArena();
        }
        return statusIArena.map(status -> status.getOppfolgingsenhet()).orElse(null);
    }

    Boolean getInaktivIArena() {
        return inaktivIArena;
    }

    Boolean getKanReaktiveres() {
        return kanReaktiveres;
    }

    Boolean getErIkkeArbeidssokerUtenOppfolging() {
        return erIkkeArbeidssokerUtenOppfolging;
    }

    void avsluttOppfolging(String veileder, String begrunnelse) {
        if (!kanAvslutteOppfolging()) {
            log.info("Avslutting av oppfølging ikke tillatt");
            return;
        }

        if (Optional.ofNullable(oppfolging.getGjeldendeEskaleringsvarsel()).isPresent()) {
            stoppEskalering("Eskalering avsluttet fordi oppfølging ble avsluttet");
        }

        deps.getOppfolgingRepository().avsluttOppfolging(aktorId, veileder, begrunnelse);
    }

    private Oppfolging hentOppfolging() {
        return deps.getOppfolgingRepository().hentOppfolging(aktorId)
                .orElseGet(() -> deps.getOppfolgingRepository().opprettOppfolging(aktorId));
    }

    void startEskalering(String begrunnelse, long tilhorendeDialogId) {
        String veilederId = SubjectHandler.getSubjectHandler().getUid();
        deps.getTransactor().inTransaction(() -> {
            deps.getOppfolgingRepository().startEskalering(aktorId, veilederId, begrunnelse, tilhorendeDialogId);
            deps.getEskaleringsvarselService().sendEskaleringsvarsel(aktorId, tilhorendeDialogId);
        });
    }

    void stoppEskalering(String begrunnelse) {
        String veilederId = SubjectHandler.getSubjectHandler().getUid();
        deps.getOppfolgingRepository().stoppEskalering(aktorId, veilederId, begrunnelse);
    }

    boolean harAktivEskalering() {
        return oppfolging.getGjeldendeEskaleringsvarsel() != null;
    }

    @SneakyThrows
    private void hentOppfolgingstatusFraArena() {

        statusIArena = Try.of(() -> deps.getArenaOppfolgingService().hentArenaOppfolging(fnr))
                .toOption()
                .toJavaOptional();
    }

    private void sjekkReservasjonIKrrOgOppdaterOppfolging() {
        if (oppfolging.isUnderOppfolging()) {
            this.reservertIKrr = sjekkKrr();
            if (!manuell() && reservertIKrr) {
                deps.getOppfolgingRepository().opprettManuellStatus(
                        new ManuellStatus()
                                .setAktorId(oppfolging.getAktorId())
                                .setManuell(true)
                                .setDato(new Timestamp(currentTimeMillis()))
                                .setBegrunnelse("Reservert og under oppfølging")
                                .setOpprettetAv(SYSTEM)
                );
            }
        } else {
            this.reservertIKrr = false;
        }
    }

    @SneakyThrows
    private boolean sjekkKrr() {
        val req = new WSHentDigitalKontaktinformasjonRequest().withPersonident(fnr);
        try {
            return of(deps.getDigitalKontaktinformasjonV1().hentDigitalKontaktinformasjon(req))
                    .map(WSHentDigitalKontaktinformasjonResponse::getDigitalKontaktinformasjon)
                    .map(WSKontaktinformasjon::getReservasjon)
                    .map("true"::equalsIgnoreCase)
                    .orElse(false);
        } catch (HentDigitalKontaktinformasjonKontaktinformasjonIkkeFunnet |
                HentDigitalKontaktinformasjonPersonIkkeFunnet e) {
            log.info(e.getMessage(), e);
            return true;
        } catch (Exception e) {
            log.warn(e.getMessage(), e);
            return false;
        }
    }

    @SneakyThrows
    private void hentYtelseskontrakt() {
        val wsHentYtelseskontraktListeRequest = new WSHentYtelseskontraktListeRequest();
        wsHentYtelseskontraktListeRequest.setPersonidentifikator(fnr);
        this.ytelser = deps.getYtelseskontraktV3().hentYtelseskontraktListe(wsHentYtelseskontraktListeRequest);
    }

    private void hentArenaAktiviteter() {
        this.arenaAktiviteter = deps.getVeilarbaktivtetService().hentArenaAktiviteter(fnr);
    }

    private void avsluttKvpVedEnhetBytte() {
        Kvp gjeldendeKvp = deps.getKvpService().gjeldendeKvp(fnr);
        if (gjeldendeKvp == null) {
            return;
        }

        hentOppfolgingstatusFraArena();
        statusIArena.ifPresent(status -> {
            if (brukerHarByttetKontor(status, gjeldendeKvp)) {
                deps.getKvpService().stopKvpUtenEnhetSjekk(fnr, "KVP avsluttet automatisk pga. endret Nav-enhet", SYSTEM, this);
                FunksjonelleMetrikker.stopKvpDueToChangedUnit();
                reloadOppfolging();
            }
        });
    }

    private boolean brukerHarByttetKontor(ArenaOppfolging statusIArena, Kvp kvp) {
        return !statusIArena.getOppfolgingsenhet().equals(kvp.getEnhet());
    }

    @Component
    @Getter
    public static class OppfolgingResolverDependencies {

        @Inject
        private PepClient pepClient;

        @Inject
        private Transactor transactor;

        @Inject
        private AktorService aktorService;

        @Inject
        private OppfolgingRepository oppfolgingRepository;

        @Inject
        private ArenaOppfolgingService arenaOppfolgingService;
        
        @Inject
        private DigitalKontaktinformasjonV1 digitalKontaktinformasjonV1;

        @Inject
        private VilkarService vilkarService;

        @Inject
        private YtelseskontraktV3 ytelseskontraktV3;

        @Inject
        private VeilarbaktivtetService veilarbaktivtetService;

        @Inject
        private EskaleringsvarselService eskaleringsvarselService;

        @Inject
        private KvpRepository kvpRepository;

        @Inject
        private KvpService kvpService;

        @Inject
        private RemoteFeatureConfig.BrukervilkarFeature brukervilkarFeature;

    }
}
