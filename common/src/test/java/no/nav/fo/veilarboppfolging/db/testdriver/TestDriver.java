package no.nav.fo.veilarboppfolging.db.testdriver;

import no.nav.fo.veilarboppfolging.utils.ProxyUtils;

import java.sql.*;
import java.util.Properties;
import java.util.logging.Logger;

import static java.sql.DriverManager.registerDriver;

public class TestDriver implements Driver {

    private static int databaseCounter;

    public static final String URL = TestDriver.class.getSimpleName();

    static {
        try {
            registerDriver(new TestDriver());
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    private Driver driver = new org.h2.Driver();

    @Override
    public Connection connect(String url, Properties info) throws SQLException {
        return ProxyUtils.proxy(new ConnectionInvocationHandler(driver.connect(getH2Url(), info)), Connection.class);
    }

    private String getH2Url() {
        return String.format(
                "jdbc:h2:mem:veilarboppfolging-%s;DB_CLOSE_DELAY=-1;MODE=Oracle",
                databaseCounter++
        );
    }

    @Override
    public boolean acceptsURL(String url) throws SQLException {
        return driver.acceptsURL(url);
    }

    @Override
    public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) throws SQLException {
        return driver.getPropertyInfo(getH2Url(), info);
    }

    @Override
    public int getMajorVersion() {
        return driver.getMajorVersion();
    }

    @Override
    public int getMinorVersion() {
        return driver.getMinorVersion();
    }

    @Override
    public boolean jdbcCompliant() {
        return driver.jdbcCompliant();
    }

    @Override
    public Logger getParentLogger() throws SQLFeatureNotSupportedException {
        return driver.getParentLogger();
    }

}
