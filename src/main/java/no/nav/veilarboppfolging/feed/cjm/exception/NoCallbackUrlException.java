package no.nav.veilarboppfolging.feed.cjm.exception;

import no.nav.veilarboppfolging.feed.cjm.common.FeedWebhookResponse;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

import static javax.ws.rs.core.Response.Status.BAD_REQUEST;

public class NoCallbackUrlException extends WebApplicationException {
    public NoCallbackUrlException() {
        super(
                Response
                        .status(BAD_REQUEST)
                        .entity(new FeedWebhookResponse().setMelding("Request må inneholde webhookCallback-url"))
                        .build()
        );
    }
}
