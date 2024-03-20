package io.github.emotionbug.jdbc.sshj;

import java.sql.Array;
import java.sql.Blob;
import java.sql.CallableStatement;
import java.sql.Clob;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.NClob;
import java.sql.PreparedStatement;
import java.sql.SQLClientInfoException;
import java.sql.SQLException;
import java.sql.SQLWarning;
import java.sql.SQLXML;
import java.sql.Savepoint;
import java.sql.Statement;
import java.sql.Struct;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Executor;

/**
 * @author boky
 */
public class SshConnection implements Connection {

  final Connection wrapped;
  final AbstractTunnel tunnel;

  SshConnection(AbstractTunnel tunnel, Connection wrapped) {
    this.tunnel = tunnel;
    this.wrapped = wrapped;

    tunnel.add(this);
  }

  @Override
  public Statement createStatement() throws SQLException {
    return wrapped.createStatement();
  }

  @Override
  public PreparedStatement prepareStatement(String sql) throws SQLException {
    return wrapped.prepareStatement(sql);
  }

  @Override
  public CallableStatement prepareCall(String sql) throws SQLException {
    return wrapped.prepareCall(sql);
  }

  @Override
  public String nativeSQL(String sql) throws SQLException {
    return wrapped.nativeSQL(sql);
  }

  @Override
  public boolean getAutoCommit() throws SQLException {
    return wrapped.getAutoCommit();
  }

  @Override
  public void setAutoCommit(boolean autoCommit) throws SQLException {
    wrapped.setAutoCommit(autoCommit);
  }

  @Override
  public void commit() throws SQLException {
    wrapped.commit();
  }

  @Override
  public void rollback() throws SQLException {
    wrapped.rollback();
  }

  @Override
  public void close() throws SQLException {
    try {
      wrapped.close();
    } finally {
      tunnel.remove(this);
    }
  }

  @Override
  public boolean isClosed() throws SQLException {
    return wrapped.isClosed();
  }

  @Override
  public DatabaseMetaData getMetaData() throws SQLException {
    return wrapped.getMetaData();
  }

  @Override
  public boolean isReadOnly() throws SQLException {
    return wrapped.isReadOnly();
  }

  @Override
  public void setReadOnly(boolean readOnly) throws SQLException {
    wrapped.setReadOnly(readOnly);
  }

  @Override
  public String getCatalog() throws SQLException {
    return wrapped.getCatalog();
  }

  @Override
  public void setCatalog(String catalog) throws SQLException {
    wrapped.setCatalog(catalog);
  }

  @Override
  public int getTransactionIsolation() throws SQLException {
    return wrapped.getTransactionIsolation();
  }

  @Override
  public void setTransactionIsolation(int level) throws SQLException {
    wrapped.setTransactionIsolation(level);
  }

  @Override
  public SQLWarning getWarnings() throws SQLException {
    return wrapped.getWarnings();
  }

  @Override
  public void clearWarnings() throws SQLException {
    wrapped.clearWarnings();
  }

  @Override
  public Statement createStatement(int resultSetType, int resultSetConcurrency)
      throws SQLException {
    return wrapped.createStatement(resultSetType, resultSetConcurrency);
  }

  @Override
  public PreparedStatement prepareStatement(String sql, int resultSetType, int resultSetConcurrency)
      throws SQLException {
    return wrapped.prepareStatement(sql, resultSetType, resultSetConcurrency);
  }

  @Override
  public CallableStatement prepareCall(String sql, int resultSetType, int resultSetConcurrency)
      throws SQLException {
    return wrapped.prepareCall(sql, resultSetType, resultSetConcurrency);
  }

  @Override
  public Map<String, Class<?>> getTypeMap() throws SQLException {
    return wrapped.getTypeMap();
  }

  @Override
  public void setTypeMap(Map<String, Class<?>> map) throws SQLException {
    wrapped.setTypeMap(map);
  }

  @Override
  public int getHoldability() throws SQLException {
    return wrapped.getHoldability();
  }

  @Override
  public void setHoldability(int holdability) throws SQLException {
    wrapped.setHoldability(holdability);
  }

  @Override
  public Savepoint setSavepoint() throws SQLException {
    return wrapped.setSavepoint();
  }

  @Override
  public Savepoint setSavepoint(String name) throws SQLException {
    return wrapped.setSavepoint(name);
  }

  @Override
  public void rollback(Savepoint savepoint) throws SQLException {
    wrapped.rollback(savepoint);
  }

  @Override
  public void releaseSavepoint(Savepoint savepoint) throws SQLException {
    wrapped.releaseSavepoint(savepoint);
  }

  @Override
  public Statement createStatement(int resultSetType, int resultSetConcurrency,
                                   int resultSetHoldability) throws SQLException {
    return wrapped.createStatement(resultSetType, resultSetConcurrency, resultSetHoldability);
  }

  @Override
  public PreparedStatement prepareStatement(String sql, int resultSetType, int resultSetConcurrency,
                                            int resultSetHoldability) throws SQLException {
    return wrapped.prepareStatement(sql, resultSetType, resultSetConcurrency, resultSetHoldability);
  }

  @Override
  public CallableStatement prepareCall(String sql, int resultSetType, int resultSetConcurrency,
                                       int resultSetHoldability) throws SQLException {
    return wrapped.prepareCall(sql, resultSetType, resultSetConcurrency, resultSetHoldability);
  }

  @Override
  public PreparedStatement prepareStatement(String sql, int autoGeneratedKeys) throws SQLException {
    return wrapped.prepareStatement(sql, autoGeneratedKeys);
  }

  @Override
  public PreparedStatement prepareStatement(String sql, int[] columnIndexes) throws SQLException {
    return wrapped.prepareStatement(sql, columnIndexes);
  }

  @Override
  public PreparedStatement prepareStatement(String sql, String[] columnNames) throws SQLException {
    return wrapped.prepareStatement(sql, columnNames);
  }

  @Override
  public Clob createClob() throws SQLException {
    return wrapped.createClob();
  }

  @Override
  public Blob createBlob() throws SQLException {
    return wrapped.createBlob();
  }

  @Override
  public NClob createNClob() throws SQLException {
    return wrapped.createNClob();
  }

  @Override
  public SQLXML createSQLXML() throws SQLException {
    return wrapped.createSQLXML();
  }

  @Override
  public boolean isValid(int timeout) throws SQLException {
    return wrapped.isValid(timeout);
  }

  @Override
  public void setClientInfo(String name, String value) throws SQLClientInfoException {
    wrapped.setClientInfo(name, value);
  }

  @Override
  public String getClientInfo(String name) throws SQLException {
    return wrapped.getClientInfo(name);
  }

  @Override
  public Properties getClientInfo() throws SQLException {
    return wrapped.getClientInfo();
  }

  @Override
  public void setClientInfo(Properties properties) throws SQLClientInfoException {
    wrapped.setClientInfo(properties);
  }

  @Override
  public Array createArrayOf(String typeName, Object[] elements) throws SQLException {
    return wrapped.createArrayOf(typeName, elements);
  }

  @Override
  public Struct createStruct(String typeName, Object[] attributes) throws SQLException {
    return wrapped.createStruct(typeName, attributes);
  }

  @Override
  public String getSchema() throws SQLException {
    return wrapped.getSchema();
  }

  @Override
  public void setSchema(String schema) throws SQLException {
    wrapped.setSchema(schema);
  }

  @Override
  public void abort(Executor executor) throws SQLException {
    wrapped.abort(executor);
  }

  @Override
  public void setNetworkTimeout(Executor executor, int milliseconds) throws SQLException {
    wrapped.setNetworkTimeout(executor, milliseconds);
  }

  @Override
  public int getNetworkTimeout() throws SQLException {
    return wrapped.getNetworkTimeout();
  }

  @Override
  public <T> T unwrap(Class<T> iface) throws SQLException {
    //noinspection unchecked
    return iface.isInstance(wrapped) ? (T) wrapped : wrapped.unwrap(iface);
  }

  @Override
  public boolean isWrapperFor(Class<?> iface) throws SQLException {
    return iface.isInstance(wrapped) || wrapped.isWrapperFor(iface);
  }
}

