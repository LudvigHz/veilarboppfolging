package no.nav.veilarboppfolging.controller.v2;

import lombok.RequiredArgsConstructor;
import no.nav.common.types.identer.AktorId;
import no.nav.common.types.identer.Fnr;
import no.nav.veilarboppfolging.controller.response.AvslutningStatus;
import no.nav.veilarboppfolging.controller.response.OppfolgingPeriodeDTO;
import no.nav.veilarboppfolging.controller.response.OppfolgingPeriodeMinimalDTO;
import no.nav.veilarboppfolging.controller.response.OppfolgingStatus;
import no.nav.veilarboppfolging.controller.v2.request.AvsluttOppfolgingV2Request;
import no.nav.veilarboppfolging.controller.v2.response.UnderOppfolgingV2Response;
import no.nav.veilarboppfolging.service.AuthService;
import no.nav.veilarboppfolging.service.OppfolgingService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.stream.Collectors;

import static no.nav.veilarboppfolging.utils.DtoMappers.*;

@RestController
@RequestMapping("/api/v2/oppfolging")
@RequiredArgsConstructor
public class OppfolgingV2Controller {

    private final OppfolgingService oppfolgingService;

    private final AuthService authService;

    @GetMapping("/niva3")
    public UnderOppfolgingV2Response underOppfolgingNiva3() {
        Fnr fnr = Fnr.of(authService.getInnloggetBrukerIdent());
        return new UnderOppfolgingV2Response(oppfolgingService.erUnderOppfolgingNiva3(fnr));
    }

    @GetMapping
    public UnderOppfolgingV2Response underOppfolging(@RequestParam(value = "fnr", required = false) Fnr fnr) {
        // TODO: Hvis dette endepunktet kun blir brukt av interne brukere så kan vi gjøre fnr query param required
        Fnr fodselsnummer = authService.hentIdentForEksternEllerIntern(fnr);
        return new UnderOppfolgingV2Response(oppfolgingService.erUnderOppfolging(fodselsnummer));
    }

    @GetMapping("/status")
    public OppfolgingStatus hentOppfolgingsStatus(@RequestParam(value = "fnr", required = false) Fnr fnr) {
        Fnr fodselsnummer = authService.hentIdentForEksternEllerIntern(fnr);
        return tilDto(oppfolgingService.hentOppfolgingsStatus(fodselsnummer), authService.erInternBruker());
    }

    @PostMapping("/start")
    public ResponseEntity<?> startOppfolging(@RequestParam("fnr") Fnr fnr) {
        authService.skalVereInternBruker();
        oppfolgingService.startOppfolging(fnr);

        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @PostMapping("/avslutt")
    public ResponseEntity<?> avsluttOppfolging(@RequestBody AvsluttOppfolgingV2Request request) {
        authService.skalVereInternBruker();
        oppfolgingService.avsluttOppfolging(request.getFnr(), request.getVeilederId().get(), request.getBegrunnelse());

        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @GetMapping("/avslutning-status")
    public AvslutningStatus hentAvslutningStatus(@RequestParam("fnr") Fnr fnr) {
        authService.skalVereInternBruker();
        return tilDto(oppfolgingService.hentAvslutningStatus(fnr));
    }

    @GetMapping("/periode/{uuid}")
    public OppfolgingPeriodeMinimalDTO hentOppfolgingsPeriode(@PathVariable("uuid") String uuid){
        var maybePeriode = oppfolgingService.hentOppfolgingsperiode(uuid);

        if (maybePeriode.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }

        var periode = maybePeriode.get();

        authService.sjekkLesetilgangMedAktorId(AktorId.of(periode.getAktorId()));

        return tilOppfolgingPeriodeMinimalDTO(periode);
    }

    @GetMapping("/perioder")
    public List<OppfolgingPeriodeDTO> hentOppfolgingsperioder(@RequestParam("fnr") Fnr fnr) {
        authService.skalVereSystemBruker();

        return oppfolgingService.hentOppfolgingsperioder(fnr)
                .stream()
                .map(op -> tilOppfolgingPeriodeDTO(op, true))
                .collect(Collectors.toList());
    }

}
