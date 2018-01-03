package no.nav.fo.veilarboppfolging.rest;

import io.swagger.annotations.Api;
import no.nav.apiapp.security.PepClient;
import no.nav.dialogarena.aktor.AktorService;
import no.nav.fo.feed.producer.FeedProducer;
import no.nav.fo.veilarboppfolging.db.VeilederTilordningerRepository;
import no.nav.fo.veilarboppfolging.rest.domain.OppfolgingFeedDTO;
import no.nav.fo.veilarboppfolging.rest.domain.TilordneVeilederResponse;
import no.nav.fo.veilarboppfolging.rest.domain.VeilederTilordning;
import no.nav.sbl.dialogarena.common.abac.pep.exception.PepException;
import org.slf4j.Logger;
import org.springframework.stereotype.Component;

import javax.ws.rs.*;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;

import static org.slf4j.LoggerFactory.getLogger;

@Component
@Path("")
@Api(value = "VeilederTilordningRessurs")
public class VeilederTilordningRessurs {

    private static final Logger LOG = getLogger(VeilederTilordningRessurs.class);

    private AktorService aktorService;
    private VeilederTilordningerRepository veilederTilordningerRepository;
    private final PepClient pepClient;

    private FeedProducer<OppfolgingFeedDTO> feed;

    public VeilederTilordningRessurs(AktorService aktorService,
                                     VeilederTilordningerRepository veilederTilordningerRepository,
                                     PepClient pepClient,
                                     FeedProducer<OppfolgingFeedDTO> feed) {
        this.aktorService = aktorService;
        this.veilederTilordningerRepository = veilederTilordningerRepository;
        this.pepClient = pepClient;
        this.feed = feed;
    }

    @POST
    @Consumes("application/json")
    @Produces("application/json")
    @Path("/tilordneveileder")
    public Response postVeilederTilordninger(List<VeilederTilordning> tilordninger) {
        List<VeilederTilordning> feilendeTilordninger = new ArrayList<>();

        for (VeilederTilordning tilordning : tilordninger) {
            try {
                final String fnr = tilordning.getBrukerFnr();
                pepClient.sjekkSkriveTilgangTilFnr(fnr);

                String aktoerId = finnAktorId(fnr);

                String tilordningForAktoer = veilederTilordningerRepository.hentTilordningForAktoer(aktoerId);

                if (kanSetteNyVeileder(tilordningForAktoer, tilordning.getFraVeilederId())) {
                    skrivTilDatabase(aktoerId, tilordning.getTilVeilederId());
                } else {
                    feilendeTilordninger.add(tilordning);
                    LOG.info("Aktoerid {} kunne ikke tildeles ettersom fraVeileder er feil", aktoerId);
                }
            } catch (Exception e) {
                feilendeTilordninger.add(tilordning);
                loggFeilOppfolging(e);
            }
        }

        TilordneVeilederResponse response = new TilordneVeilederResponse().setFeilendeTilordninger(feilendeTilordninger);

        if (feilendeTilordninger.isEmpty()) {
            response.setResultat("OK: Veiledere tilordnet");
        } else {
            response.setResultat("WARNING: Noen brukere kunne ikke tilordnes en veileder");
        }
        if (tilordninger.size() > feilendeTilordninger.size()) {
            kallWebhook();
        }
        return Response.ok().entity(response).build();

    }

    private void kallWebhook() {
        try {
            feed.activateWebhook();
        } catch (Exception e) {
            // Logger feilen, men bryr oss ikke om det. At webhooken feiler påvirker ikke funksjonaliteten
            // men gjør at endringen kommer senere inn i portefølje
            LOG.warn("Webhook feilet", e);
        }
    }

    private String finnAktorId(final String fnr) {
        return aktorService.getAktorId(fnr)
                .orElseThrow(() -> new IllegalArgumentException("Aktoerid ikke funnet"));
    }

    private void loggFeilOppfolging(Exception e) {
        if(e instanceof NotAuthorizedException) {
            LOG.warn("Request is not authorized", e);
        } else {
            LOG.error(loggMeldingForException(e), e);
        }
    }

    private String loggMeldingForException(Exception e) {
        return (e instanceof PepException) ? "Kall til ABAC feilet"
                : (e instanceof IllegalArgumentException) ? "Aktoerid ikke funnet"
                : "Det skjedde en feil ved tildeling av veileder";
    }

    private void skrivTilDatabase(String aktoerId, String veileder) {
        try {
            veilederTilordningerRepository.upsertVeilederTilordning(aktoerId, veileder);
            LOG.debug(String.format("Veileder %s tilordnet aktoer %s", veileder, aktoerId));
        } catch (Exception e) {
            LOG.error(String.format("Kunne ikke tilordne veileder %s til aktoer %s", veileder, aktoerId), e);
            throw e;
        }
    }

    static boolean kanSetteNyVeileder(String eksisterendeVeileder, String fraVeileder) {
        return eksisterendeVeileder == null || eksisterendeVeileder.equals(fraVeileder);
    }
}