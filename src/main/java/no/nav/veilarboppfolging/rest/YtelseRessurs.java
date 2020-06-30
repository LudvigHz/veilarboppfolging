package no.nav.veilarboppfolging.rest;

import io.swagger.annotations.Api;
import no.nav.dialogarena.aktor.AktorService;
import no.nav.veilarboppfolging.domain.OppfolgingskontraktResponse;
import no.nav.veilarboppfolging.utils.mappers.OppfolgingMapper;
import no.nav.veilarboppfolging.utils.mappers.YtelseskontraktMapper;
import no.nav.veilarboppfolging.rest.domain.YtelserResponse;
import no.nav.veilarboppfolging.rest.domain.YtelseskontraktResponse;
import no.nav.veilarboppfolging.client.ArenaOppfolgingService;
import no.nav.veilarboppfolging.client.YtelseskontraktService;
import no.nav.sbl.dialogarena.common.abac.pep.exception.PepException;
import org.slf4j.Logger;
import org.springframework.stereotype.Component;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.xml.datatype.XMLGregorianCalendar;
import java.time.LocalDate;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import static no.nav.veilarboppfolging.utils.CalendarConverter.convertDateToXMLGregorianCalendar;
import static org.slf4j.LoggerFactory.getLogger;

@Path("/person/{fnr}")
@Component
@Produces(APPLICATION_JSON)
@Api(value = "Ytelser")
public class YtelseRessurs {
    private static final Logger LOG = getLogger(YtelseRessurs.class);
    private static final int MANEDER_BAK_I_TID = 2;
    private static final int MANEDER_FREM_I_TID = 1;

    final private YtelseskontraktService ytelseskontraktService;
    final private ArenaOppfolgingService arenaOppfolgingService;
    final private OppfolgingMapper oppfolgingMapper;
    final private YtelseskontraktMapper ytelseskontraktMapper;
    private final AutorisasjonService autorisasjonService;
    private final AktorService aktorService;


    public YtelseRessurs(YtelseskontraktService ytelseskontraktService,
                         ArenaOppfolgingService arenaOppfolgingService,
                         OppfolgingMapper oppfolgingMapper,
                         YtelseskontraktMapper ytelseskontraktMapper,
                         AutorisasjonService autorisasjonService,
                         AktorService aktorService) {
        this.ytelseskontraktService = ytelseskontraktService;
        this.arenaOppfolgingService = arenaOppfolgingService;
        this.oppfolgingMapper = oppfolgingMapper;
        this.ytelseskontraktMapper = ytelseskontraktMapper;
        this.autorisasjonService = autorisasjonService;
        this.aktorService = aktorService;
    }

    @GET
    @Path("/ytelser")
    public YtelserResponse getYtelser(@PathParam("fnr") String fnr) throws PepException {
        autorisasjonService.skalVereInternBruker();
        autorisasjonService.sjekkLesetilgangTilBruker(fnr);

        LocalDate periodeFom = LocalDate.now().minusMonths(MANEDER_BAK_I_TID);
        LocalDate periodeTom = LocalDate.now().plusMonths(MANEDER_FREM_I_TID);
        XMLGregorianCalendar fom = convertDateToXMLGregorianCalendar(periodeFom);
        XMLGregorianCalendar tom = convertDateToXMLGregorianCalendar(periodeTom);

        LOG.info("Henter ytelse for fnr");
        final YtelseskontraktResponse ytelseskontraktResponse = ytelseskontraktMapper.tilYtelseskontrakt(ytelseskontraktService.hentYtelseskontraktListe(fom, tom, fnr));
        final OppfolgingskontraktResponse oppfolgingskontraktResponse = oppfolgingMapper.tilOppfolgingskontrakt(arenaOppfolgingService.hentOppfolgingskontraktListe(fom, tom, fnr));

        return new YtelserResponse()
                .withVedtaksliste(ytelseskontraktResponse.getVedtaksliste())
                .withYtelser(ytelseskontraktResponse.getYtelser())
                .withOppfoelgingskontrakter(oppfolgingskontraktResponse.getOppfoelgingskontrakter());
    }
}
