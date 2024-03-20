package io.github.emotionbug.jdbc.sshj;

import java.io.IOException;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.Enumeration;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractSshJDriver implements Driver {

  static final Map<String, AtomicReference<AbstractTunnel>> tunnelList = new ConcurrentHashMap<>();
  private static final org.slf4j.Logger log = LoggerFactory.getLogger(AbstractSshJDriver.class);

  abstract String getDriverPrefix();

  @Override
  public boolean acceptsURL(String url) throws SQLException {
    return (url != null && url.startsWith(getDriverPrefix()));
  }

  private Driver findDriver(String url) throws SQLException {
    Driver realDriver = null;

    for (Enumeration<Driver> drivers = DriverManager.getDrivers(); drivers.hasMoreElements(); ) {
      try {
        Driver driver = drivers.nextElement();

        if (driver.acceptsURL(url)) {
          realDriver = driver;
          break;
        }
      } catch (SQLException e) {
        // Ignore, this is fine
      }
    }

    if (realDriver == null) {
      throw new SQLException("Unable to find a driver that accepts " + url);
    }

    return realDriver;
  }

  protected Connection getRealConnection(AbstractTunnel tunnel, Properties info, String originalUrl,
                                         String newHost, String newPort) throws SQLException {
    originalUrl = originalUrl.replaceAll("\\{\\{[hH][oO][sS][tT]\\}\\}", newHost);
    originalUrl = originalUrl.replaceAll("\\{\\{[pP][oO][rR][tT]\\}\\}", newPort);

    Driver driver = findDriver(originalUrl);
    return driver.connect(originalUrl, info);
  }

  protected ConnectionData verifyConnection(String url) throws SQLException {
    if (url == null) {
      throw new SQLException("URL is required");
    }

    if (!acceptsURL(url)) {
      return null;
    }

    final String[] split = url.split(";;;", 2);
    if (split.length != 2) {
      throw new SQLException(
          "Please provide the original database URL after the "
              + "SSH settings by including three semi-colons (;;;) and the original URL.");
    }
    final String ourUrl = split[0];
    String forwardingUrl = split[1];
    if (ourUrl.length() == 0) {
      throw new SQLException("Missing SSHJ URL!");
    }

    if (!forwardingUrl.toLowerCase().startsWith("jdbc:")) {
      throw new SQLException("You need to supply the actual URL to connect to!");
    }

    return new ConnectionData(
        ourUrl,
        forwardingUrl
    );
  }


  @Override
  public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) throws SQLException {
    return findDriver(url).getPropertyInfo(url, info);
  }

  @Override
  public boolean jdbcCompliant() {
    return true;
  }

  @Override
  public Logger getParentLogger() throws SQLFeatureNotSupportedException {
    throw new SQLFeatureNotSupportedException("Feature not supported");
  }

  @Override
  public Connection connect(String url, Properties info) throws SQLException {
    ConnectionData d = verifyConnection(url);
    // Not our connection URL, skip further integration
    if (d == null) {
      return null;
    }

    AbstractTunnel tunnel = getTunnel(url, d);
    tunnel.ensureStarted();
    Connection c = getRealConnection(tunnel, info, d.getForwardingUrl(), tunnel.getLocalHost(),
        tunnel.getLocalPort());
    return new SshConnection(tunnel, c);
  }

  @SuppressWarnings("SynchronizationOnLocalVariableOrMethodParameter")
  public AbstractTunnel getTunnel(String url, ConnectionData d) throws SQLException {
    AbstractTunnel tunnel;
    try {
      AtomicReference<AbstractTunnel> a = tunnelList.get(url);
      if (a == null) {
        tunnel = newTunnel(d);
        log.info("No tunnel for {}, created a new tunnel: {}", url, tunnel);
        a = new AtomicReference<>(tunnel);
        synchronized (a) {
          tunnelList.put(url, a);
          tunnel.start();
        }
      } else {
        synchronized (a) {
          tunnel = a.get();
          if (tunnel.isStopped() || !tunnel.isListening()) {
            tunnel = newTunnel(d);
            log.info("Tunnel stopped for {}, created a new tunnel: {}", url, tunnel);
            a.set(tunnel);
          } else {
            log.debug("Reusing connection {}:{}", tunnel.getLocalHost(), tunnel.getLocalPort());
          }
        }
      }
    } catch (IOException e) {
      throw new SQLException(e);
    }
    return tunnel;
  }

  protected abstract AbstractTunnel newTunnel(ConnectionData d) throws IOException, SQLException;

}
