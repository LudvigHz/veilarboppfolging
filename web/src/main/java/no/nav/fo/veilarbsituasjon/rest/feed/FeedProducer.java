package no.nav.fo.veilarbsituasjon.rest.feed;

import javaslang.control.Try;
import lombok.Builder;
import no.nav.fo.veilarbsituasjon.domain.OppfolgingBruker;
import no.nav.fo.veilarbsituasjon.exception.HttpNotSupportedException;
import no.nav.fo.veilarbsituasjon.services.TilordningService;
import org.slf4j.Logger;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.core.Response;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

import static javaslang.API.Case;
import static javaslang.API.Match;
import static javaslang.Predicates.instanceOf;
import static javax.ws.rs.core.Response.Status.BAD_REQUEST;
import static no.nav.fo.veilarbsituasjon.rest.feed.UrlValidator.validateUrl;
import static org.slf4j.LoggerFactory.getLogger;

@Builder
public class FeedProducer {

    private static final Logger LOG = getLogger(FeedProducer.class);

    private int maxPageSize;
    private String webhookUrl;
    private String callbackUrl;

    public Response createFeedResponse(FeedRequest request, TilordningService service) {
        int pageSize = setPageSize(request.pageSize, maxPageSize);
        LocalDateTime sinceId = LocalDateTime.parse(request.sinceId, DateTimeFormatter.ISO_DATE_TIME);
        List<OppfolgingBruker> feedElements = service.hentTilordninger(sinceId, pageSize);
        return Response.ok().entity(feedElements).build();
    }

    private static int setPageSize(int pageSize, int maxPageSize) {
        return pageSize > maxPageSize ? maxPageSize : pageSize;
    }

    public void activateWebhook() {
        Client client = ClientBuilder.newBuilder().build();
        Response response = client.target(webhookUrl).request().build("HEAD").invoke();
        if (response.getStatus() != 200) {
            LOG.warn("Fikk respons {} ved aktivering av webhook", response.getStatus());
        }
    }

    public Response getWebhook() {
        return Response.ok().entity(webhookUrl).build();
    }

    public Response createWebhook(String callbackUrl) {
        if (callbackUrl == null) {
            return Response.status(BAD_REQUEST).entity("Respons må inneholde callback-url").build();
        }

        if (callbackUrl.equals(webhookUrl)) {
            return Response.ok().build();
        }

        Try.of(() -> {
            validateUrl(callbackUrl);
            webhookUrl = callbackUrl;
            URI uri = new URI("tilordninger/webhook");
            return Response.created(uri).build();

        }).recover(e -> Match(e).of(
                Case(instanceOf(URISyntaxException.class),
                        Response.serverError().entity("Det skjedde en feil web opprettelsen av webhook").build()),
                Case(instanceOf(MalformedURLException.class),
                        Response.status(BAD_REQUEST).entity("Feil format på callback-url").build()),
                Case(instanceOf(HttpNotSupportedException.class),
                        Response.status(BAD_REQUEST).entity("Angitt url for webhook må være HTTPS").build())
        ));

        return Response.serverError().entity("Det skjedde en feil ved opprettelse av webhook").build();
    }
}
