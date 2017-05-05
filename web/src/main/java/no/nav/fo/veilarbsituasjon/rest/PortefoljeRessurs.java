package no.nav.fo.veilarbsituasjon.rest;

import io.swagger.annotations.Api;
import no.nav.fo.veilarbsituasjon.db.BrukerRepository;
import no.nav.fo.veilarbsituasjon.domain.OppfolgingBruker;
import no.nav.fo.veilarbsituasjon.rest.domain.TilordneVeilederResponse;
import no.nav.fo.veilarbsituasjon.rest.domain.VeilederTilordning;
import no.nav.fo.veilarbsituasjon.rest.feed.FeedProducer;
import no.nav.fo.veilarbsituasjon.rest.feed.FeedRequest;
import no.nav.fo.veilarbsituasjon.services.AktoerIdService;
import no.nav.fo.veilarbsituasjon.services.PepClient;
import no.nav.fo.veilarbsituasjon.services.TilordningService;
import org.slf4j.Logger;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;

import static org.slf4j.LoggerFactory.getLogger;

@Component
@Path("")
@Api(value = "Portefolje")
public class PortefoljeRessurs {

    private static final Logger LOG = getLogger(PortefoljeRessurs.class);

    @Inject
    private TilordningService tilordningService;

    private AktoerIdService aktoerIdService;
    private BrukerRepository brukerRepository;
    private final PepClient pepClient;
    private List<VeilederTilordning> feilendeTilordninger;
    private FeedProducer feed;

    public PortefoljeRessurs(AktoerIdService aktoerIdService, BrukerRepository brukerRepository, PepClient pepClient) {
        this.aktoerIdService = aktoerIdService;
        this.brukerRepository = brukerRepository;
        this.pepClient = pepClient;

        this.feed = FeedProducer
                .builder()
                .maxPageSize(10000)
                .build();
    }

    @GET
    @Path("/tilordninger/webhook")
    public Response getWebhook() {
        return feed.getWebhook();
    }

    @PUT
    @Path("/tilordninger/webhook")
    public Response putWebhook(String callbackUrl) {
        return feed.createWebhook();
    }

    @GET
    @Path("/tilordninger")
    @Produces("application/json")
    public Response getTilordninger(@BeanParam FeedRequest request) {
        return feed.createFeedResponse(request, tilordningService);
    }

    @POST
    @Consumes("application/json")
    @Produces("application/json")
    @Path("/tilordneveileder")
    public Response postVeilederTilordninger(List<VeilederTilordning> tilordninger) {
        feilendeTilordninger = new ArrayList<>();

        for (VeilederTilordning tilordning : tilordninger) {

            final String fnr = tilordning.getBrukerFnr();
            pepClient.isServiceCallAllowed(fnr);
            String aktoerId = aktoerIdService.findAktoerId(fnr);

            OppfolgingBruker bruker = new OppfolgingBruker()
                    .setVeileder(tilordning.getTilVeilederId())
                    .setAktoerid(aktoerId);

            settVeilederDersomFraVeilederErOK(bruker, tilordning);
        }

        TilordneVeilederResponse response = new TilordneVeilederResponse()
                .setFeilendeTilordninger(feilendeTilordninger);

        if (feilendeTilordninger.isEmpty()) {
            response.setResultat("Veiledere tilordnet!");
            feed.activateWebhook();
            return Response.ok().entity(response).build();
        } else {
            response.setResultat("Noen brukere kunne ikke tilordnes en veileder.");
            return Response.ok().entity(response).build();
        }
    }


    @Transactional
    private void skrivTilDatabase(OppfolgingBruker bruker) {
        try {
            brukerRepository.leggTilEllerOppdaterBruker(bruker);
            LOG.debug(String.format("Veileder %s tilordnet aktoer %s", bruker.getVeileder(), bruker.getAktoerid()));
        } catch (Exception e) {
            LOG.error(String.format("Kunne ikke tilordne veileder %s til aktoer %s", bruker.getVeileder(), bruker.getAktoerid()), e);
            throw e;
        }
    }

    private void settVeilederDersomFraVeilederErOK(OppfolgingBruker bruker, VeilederTilordning tilordning) {
        String eksisterendeVeileder = brukerRepository.hentVeilederForAktoer(bruker.getAktoerid());
        Boolean fraVeilederErOk = eksisterendeVeileder == null || eksisterendeVeileder.equals(tilordning.getFraVeilederId());

        if (fraVeilederErOk) {
            skrivTilDatabase(bruker);
        } else {
            feilendeTilordninger.add(tilordning);
            LOG.info("Aktoerid {} kunne ikke tildeles ettersom fraVeileder er feil", bruker.getAktoerid());
        }
    }

    static boolean kanSetteNyVeileder(String fraVeileder, String tilVeileder, String eksisterendeVeileder) {
        if (tilVeileder == null) {
            return false;
        }
        return eksisterendeVeileder == null || eksisterendeVeileder.equals(fraVeileder);
    }
}