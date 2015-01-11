package com.m11n.jdbc.ssh;

import com.m11n.jdbc.ssh.util.BogusPasswordAuthenticator;
import org.apache.sshd.SshServer;
import org.apache.sshd.common.KeyPairProvider;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.CommandFactory;
import org.apache.sshd.server.PublickeyAuthenticator;
import org.apache.sshd.server.auth.CachingPublicKeyAuthenticator;
import org.apache.sshd.server.command.UnknownCommand;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.session.ServerSession;
import org.h2.tools.Server;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyPair;
import java.security.PublicKey;
import java.sql.*;
import java.util.Enumeration;
import java.util.Map;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class JdbcSshDriverTest {
    private static final Logger logger = LoggerFactory.getLogger(JdbcSshDriverTest.class);

    private String url;

    private Server dbServer;

    @Before
    public void setUp() throws Exception {
        url = System.getProperty("url");

        dbServer = Server.createTcpServer("-tcpPort" , "9292" , "-tcpAllowOthers").start();

        logger.info("Database server status: {}", dbServer.getStatus());
    }

    @After
    public void shutdown() throws Exception {
        dbServer.stop();
    }

    @Test
    public void testDriverRegistration() throws SQLException {
        boolean found = false;

        for(Enumeration<Driver> drivers = DriverManager.getDrivers(); drivers.hasMoreElements();) {
            Driver driver = drivers.nextElement();

            if(driver.getClass().equals(JdbcSshDriver.class)) {
                found = true;
                break;
            }
        }

        assertTrue(found);
    }

    @Test
    public void testMetadata() throws Exception {
        SshServer sshd = createTestSshServer();

        Connection connection = DriverManager.getConnection(url);

        DatabaseMetaData metadata = connection.getMetaData();

        // Get all the tables and views
        String[] tableType = {"TABLE"};
        java.sql.ResultSet tables = metadata.getTables(null, null, "%", tableType);

        assertNotNull(tables);

        String tableName;
        while (tables.next()) {
            tableName = tables.getString(3);

            logger.info("Table: {}", tableName);
        }
    }


    private SshServer createTestSshServer() throws Exception {
        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider("target/hostkey.rsa", "RSA"));
        //sshd.setShellFactory(new EchoShellFactory());
        sshd.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd.setCommandFactory(new CommandFactory() {
            public Command createCommand(String command) {
                return new UnknownCommand(command);
            }
        });
        sshd.setHost("localhost");
        sshd.setPort(2222);
        //sshd.getProperties().put(SshServer.AUTH_METHODS, "publickey");
        sshd.setPublickeyAuthenticator(new TestCachingPublicKeyAuthenticator());
        sshd.start();
        sshd.getPort();

        return sshd;
    }

    public static class TestCachingPublicKeyAuthenticator extends CachingPublicKeyAuthenticator {
        private KeyPairProvider keyProvider = new SimpleGeneratorHostKeyProvider("target/hostkey.rsa", "RSA");
        private KeyPair pairRsa = keyProvider.loadKey(KeyPairProvider.SSH_RSA);

        public TestCachingPublicKeyAuthenticator() {
            super(new PublickeyAuthenticator() {
                @Override
                public boolean authenticate(String s, PublicKey publicKey, ServerSession serverSession) {
                    return true;
                }
            });
        }
        public Map<ServerSession, Map<PublicKey, Boolean>> getCache() {
            return cache;
        }
        public KeyPairProvider getKeyProvider() {
            return keyProvider;
        }
    }

}
