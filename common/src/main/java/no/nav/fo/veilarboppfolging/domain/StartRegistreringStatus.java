package no.nav.fo.veilarboppfolging.domain;

import lombok.Data;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
public class StartRegistreringStatus {
    private boolean underOppfolging;
    private boolean oppfyllerKravForAutomatiskRegistrering;
}
