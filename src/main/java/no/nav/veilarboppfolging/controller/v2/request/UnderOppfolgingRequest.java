package no.nav.veilarboppfolging.controller.v2.request;

import no.nav.common.types.identer.Fnr;

public record UnderOppfolgingRequest(
	Fnr fnr
) {
}
