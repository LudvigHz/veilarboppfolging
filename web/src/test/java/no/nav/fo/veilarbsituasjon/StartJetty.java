package no.nav.fo.veilarbsituasjon;

import no.nav.fo.security.jwt.context.JettySubjectHandler;
import no.nav.sbl.dialogarena.common.jetty.Jetty;
import org.apache.activemq.broker.BrokerService;
import org.eclipse.jetty.jaas.JAASLoginService;

import static java.lang.System.getProperty;
import static java.lang.System.setProperty;
import static no.nav.fo.veilarbsituasjon.config.JndiLocalContextConfig.setupInMemoryDatabase;
import static no.nav.fo.veilarbsituasjon.config.JndiLocalContextConfig.setupJndiLocalContext;
import static no.nav.sbl.dialogarena.common.jetty.Jetty.usingWar;

public class StartJetty {
    private static final String SUBJECT_HANDLER_KEY = "no.nav.modig.core.context.subjectHandlerImplementationClass";
    private static final int PORT = 8486;

    public static void main(String[] args) throws Exception {

        Jetty jetty = startJetty(PORT);
        jetty.start();
    }

    public static Jetty startJetty(int port) throws Exception {
        if (Boolean.parseBoolean(getProperty("lokal.database"))) {
            setupInMemoryDatabase();
        } else {
            setupJndiLocalContext();
        }

        setupBrokerService();

        JAASLoginService jaasLoginService = createJaasLoginService();
        return usingWar()
                .at("/veilarbsituasjon")
                .port(port)
                .loadProperties("/environment-test.properties")
                .overrideWebXml()
                .withLoginService(jaasLoginService)
                .buildJetty();
    }

    private static void setupBrokerService() throws Exception {
        final BrokerService broker = new BrokerService();
        broker.getSystemUsage().getTempUsage().setLimit(100 * 1024 * 1024 * 100);
        broker.getSystemUsage().getStoreUsage().setLimit(100 * 1024 * 1024 * 100);
        broker.addConnector("tcp://localhost:61616");
        broker.start();
    }

    private static JAASLoginService createJaasLoginService() {
        setProperty(SUBJECT_HANDLER_KEY, JettySubjectHandler.class.getName());
        JAASLoginService jaasLoginService = new JAASLoginService("JWT Realm");
        jaasLoginService.setLoginModuleName("jwtLogin");
        return jaasLoginService;
    }
}
