package no.nav.fo.veilarbsituasjon.config;

import no.nav.fo.inject.Database;
import no.nav.sbl.dialogarena.common.integrasjon.utils.RowMapper;
import no.nav.sbl.dialogarena.common.integrasjon.utils.SQL;
import no.nav.sbl.dialogarena.types.Pingable;
import no.nav.sbl.dialogarena.types.Pingable.Ping.PingMetadata;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.lookup.JndiDataSourceLookup;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import javax.naming.NamingException;
import javax.sql.DataSource;

@Configuration
@EnableTransactionManagement
public class DatabaseConfig {

    public static final String DATA_SOURCE_JDNI_NAME = "jdbc/veilarbsituasjonDS";

    @Bean
    public DataSource dataSourceJndiLookup() throws NamingException {
        JndiDataSourceLookup jndiDataSourceLookup = new JndiDataSourceLookup();
        jndiDataSourceLookup.setResourceRef(true);
        return jndiDataSourceLookup.getDataSource("jdbc/veilarbsituasjonDS");
    }

    @Bean
    public PlatformTransactionManager transactionManager(DataSource dataSource) {
        return new DataSourceTransactionManager(dataSource);
    }

    @Bean
    public JdbcTemplate jdbcTemplate(DataSource datasource) throws NamingException {
        return new JdbcTemplate(datasource);
    }

    @Bean
    public NamedParameterJdbcTemplate namedParameterJdbcTemplate(DataSource dataSource) {
        return new NamedParameterJdbcTemplate(dataSource);
    }

    @Bean
    public Database database(JdbcTemplate jdbcTemplates) {
        return new Database(jdbcTemplates);
    }

    @Bean
    public Pingable dbPinger(final DataSource ds) {
        PingMetadata metadata = new PingMetadata(
                "veilabrSituasjonDB: " + System.getProperty("veilarbsituasjonDB.url"),
                "Enkel spørring mot Databasen for VeilArbSituasjon.",
                true
        );
        return () -> {
            try {
                SQL.query(ds, new RowMapper.IntMapper(), "select count(1) from dual");
                return Pingable.Ping.lyktes(metadata);
            } catch (Exception e) {
                return Pingable.Ping.feilet(metadata, e);
            }
        };
    }
}
