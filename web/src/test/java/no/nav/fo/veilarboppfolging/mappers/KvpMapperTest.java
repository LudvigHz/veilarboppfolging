package no.nav.fo.veilarboppfolging.mappers;

import no.nav.fo.veilarboppfolging.domain.Kvp;
import no.nav.fo.veilarboppfolging.rest.domain.KvpDTO;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class KvpMapperTest {

    /**
     * Test that a Kvp object is correctly mapped to its DTO object.
     */
    @Test
    public void testToDTO() {
        Kvp src = Kvp.builder()
                .kvpId(1234)
                .enhet("foobar")
                .build();
        KvpDTO dest = KvpMapper.KvpToDTO(src);
        assertThat(dest.getKvpId(), is(src.getKvpId()));
        assertThat(dest.getEnhet(), is(src.getEnhet()));
    }
}