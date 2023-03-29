package edu.uiuc.ncsa.oa4mp.delegation.common.storage.monitored;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.storage.AbstractListeningStore;
import edu.uiuc.ncsa.security.storage.ListeningStoreInterface;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.data.MonitoredKeys;
import edu.uiuc.ncsa.security.storage.events.IDMap;
import edu.uiuc.ncsa.security.storage.events.LastAccessedEventListener;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionRecord;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import javax.inject.Provider;
import java.sql.*;
import java.util.List;
import java.util.UUID;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/29/23 at  10:24 AM
 */
public abstract class MonitoredSQLStore<V extends Identifiable> extends SQLStore<V> implements ListeningStoreInterface<V> {
    public MonitoredSQLStore(ConnectionPool connectionPool, Table table, Provider<V> identifiableProvider, MapConverter<V> converter) {
        super(connectionPool, table, identifiableProvider, converter);
    }

    public MonitoredSQLStore() {
    }


    AbstractListeningStore<V> listeningStore = new AbstractListeningStore<>();

    @Override
    public List<V> getMostRecent(int n, List<String> attributes) {
        return null;
    }

    @Override
    public List<LastAccessedEventListener> getLastAccessedEventListeners() {
        return listeningStore.getLastAccessedEventListeners();
    }

    @Override
    public UUID getUuid() {
        return listeningStore.getUuid();
    }

    @Override
    public void addLastAccessedEventListener(LastAccessedEventListener lastAccessedEventListener) {
        listeningStore.addLastAccessedEventListener(lastAccessedEventListener);
    }

    @Override
    public void fireLastAccessedEvent(Identifier identifier) {
        listeningStore.fireLastAccessedEvent(identifier);
    }

    @Override
    public void lastAccessUpdate(IDMap idMap) {
        MonitoredKeys keys = (MonitoredKeys) getMapConverter().getKeys();
        String sql = "update " + getTable().getFQTablename() + " set " + keys.lastAccessed() + "=?" +
                " where " + keys.identifier() + "=? AND " + keys.lastAccessed() + "<?";
        ConnectionRecord cr = getConnection();
        Connection c = cr.connection;
        try {
            PreparedStatement pStmt = c.prepareStatement(sql);
            for (Identifier id : idMap.keySet()) {
                java.sql.Date sqlDate = new Date(idMap.get(id).getTime());
                pStmt.setDate(1, sqlDate);
                pStmt.setString(2, id.toString());
                pStmt.setDate(3, sqlDate);
                pStmt.addBatch();

            }
            int[] affectedRecords = pStmt.executeBatch();
            releaseConnection(cr);

        } catch (SQLException sqlException) {
            destroyConnection(cr);
            throw new GeneralException("Unable to set last time:" + sqlException.getMessage());
        }

    }


    @Override
    public V get(Object o) {
        V v = super.get(o);
        listeningStore.fireLastAccessedEvent((Identifier) o);
        return v;
    }
}
