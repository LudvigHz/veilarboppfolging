package no.nav.fo.veilarboppfolging.rest;

import no.nav.brukerdialog.security.domain.IdentType;
import no.nav.common.auth.SsoToken;
import no.nav.common.auth.Subject;
import no.nav.common.auth.SubjectHandler;
import no.nav.fo.veilarboppfolging.db.KvpRepository;
import no.nav.fo.veilarboppfolging.domain.Kvp;
import no.nav.fo.veilarboppfolging.rest.domain.KvpDTO;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.ws.rs.core.Response;
import java.util.Date;

import static java.lang.System.setProperty;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;


@RunWith(MockitoJUnitRunner.class)
public class KvpRessursTest {

    private static final String AKTOR_ID = "1234";
    private static final long KVP_ID = 1L;
    private static final String ENHET_ID = "0001";
    public static final String AUTHORIZED_USER = "user";

    @Mock
    private KvpRepository kvpRepositoryMock;

    @InjectMocks
    private KvpRessurs kvpRessurs;

    @BeforeClass
    public static void before() {
        setProperty("no.nav.modig.security.systemuser.username", "username");
        setProperty("no.nav.modig.security.systemuser.password", "password");
    }

    @Before
    public void setup() {
        setProperty("kvp.api.brukertilgang", AUTHORIZED_USER);
    }

    @Test
    public void unauthorized_user() {
        setProperty("kvp.api.brukertilgang", "unauthorizedUser");
        Response kvpStatus = getKvpStatus();
        assertThat(kvpStatus.getStatus()).isEqualTo(403);
    }

    @Test
    public void no_active_kvp() {
        Response kvpStatus = getKvpStatus();
        assertThat(kvpStatus).isNull();
    }

    @Test
    public void with_active_kvp() {
        when(kvpRepositoryMock.gjeldendeKvp(AKTOR_ID)).thenReturn(KVP_ID);
        when(kvpRepositoryMock.fetch(KVP_ID)).thenReturn(kvp());

        Response kvpStatus = getKvpStatus();
        assertThat(kvpStatus.getStatus()).isEqualTo(200);
        KvpDTO result = (KvpDTO) kvpStatus.getEntity();
        assertThat(result.getEnhet()).isEqualTo(ENHET_ID);
    }

    @Test
    public void with_active_kvp_but_unable_to_fetch_kvp_object() {
        when(kvpRepositoryMock.gjeldendeKvp(AKTOR_ID)).thenReturn(KVP_ID);

        Response kvpStatus = getKvpStatus();
        assertThat(kvpStatus.getStatus()).isEqualTo(500);
    }

    private Response getKvpStatus() {
        Subject authorizedSubject = new Subject(AUTHORIZED_USER, IdentType.InternBruker, SsoToken.oidcToken("token"));
        return SubjectHandler.withSubject(authorizedSubject, () -> kvpRessurs.getKvpStatus(AKTOR_ID));
    }

    private Kvp kvp() {
        return Kvp.builder()
                .kvpId(KVP_ID)
                .aktorId(AKTOR_ID)
                .opprettetDato(new Date())
                .enhet(ENHET_ID)
                .build();
    }

}