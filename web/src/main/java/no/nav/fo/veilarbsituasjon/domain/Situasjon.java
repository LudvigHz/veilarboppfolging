package no.nav.fo.veilarbsituasjon.domain;

import lombok.Data;
import lombok.experimental.Accessors;

import java.util.ArrayList;
import java.util.List;

@Data
@Accessors(chain = true)
public class Situasjon {

    public boolean oppfolging;
    public String aktorId;
    public boolean manuell;
    public List<Brukervilkar> brukervilkar = new ArrayList<>();

    public Situasjon leggTilBrukervilkar(Brukervilkar brukervilkar){
        this.brukervilkar.add(brukervilkar);
        return this;
    }

}
