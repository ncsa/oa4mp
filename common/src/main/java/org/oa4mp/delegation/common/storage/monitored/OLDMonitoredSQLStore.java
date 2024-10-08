package org.oa4mp.delegation.common.storage.monitored;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.storage.MonitoredStoreDelegate;
import edu.uiuc.ncsa.security.storage.MonitoredStoreInterface;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.events.IDMap;
import edu.uiuc.ncsa.security.storage.events.LastAccessedEventListener;
import edu.uiuc.ncsa.security.storage.monitored.MonitoredKeys;
import edu.uiuc.ncsa.security.storage.monitored.upkeep.UpkeepConfiguration;
import edu.uiuc.ncsa.security.storage.monitored.upkeep.UpkeepResponse;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionRecord;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import javax.inject.Provider;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.UUID;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/29/23 at  10:24 AM
 * @deprecated Use {@link edu.uiuc.ncsa.security.storage.monitored.MonitoredSQLStore} in Sec Lib
 */
public abstract class OLDMonitoredSQLStore<V extends Identifiable> extends SQLStore<V> implements MonitoredStoreInterface<V> {
    public OLDMonitoredSQLStore(ConnectionPool connectionPool, Table table, Provider<V> identifiableProvider, MapConverter<V> converter) {
        super(connectionPool, table, identifiableProvider, converter);
    }

    public OLDMonitoredSQLStore() {
    }


    MonitoredStoreDelegate<V> listeningStore = new MonitoredStoreDelegate<>();

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
    public void fireLastAccessedEvent(MonitoredStoreInterface store, Identifier identifier) {
        listeningStore.fireLastAccessedEvent(store, identifier);
    }

    @Override
    public boolean isMonitorEnabled() {
        return listeningStore.isMonitorEnabled();
    }

    @Override

    public void setMonitorEnabled(boolean x) {
        listeningStore.setMonitorEnabled(x);
    }
     boolean DEEP_DEBUG = false;
    @Override
    public void lastAccessUpdate(IDMap idMap) {
        MonitoredKeys keys = (MonitoredKeys) getMapConverter().getKeys();
        // Note that prepared statement like "= ?" (with a space!) will not prepare correctly!
        // They seem to have the space embedded in the argument. Always use "=?"
        String sql = "update " + getTable().getFQTablename() + " set " + keys.lastAccessed() + "=?" +
                " where (" + keys.identifier() + " =?) AND (" + keys.lastAccessed() + " IS NULL OR " + keys.lastAccessed() + "<?)";
        ConnectionRecord cr = getConnection();
        Connection c = cr.connection;
        try {
            PreparedStatement pStmt = c.prepareStatement(sql);
            for (Identifier id : idMap.keySet()) {
                pStmt.setLong(1, idMap.get(id));
                pStmt.setString(2, id.toString());
                pStmt.setLong(3, idMap.get(id));
                pStmt.addBatch();
                if(DEEP_DEBUG){
                    System.out.println("OLDMonitoredSQLStore: updating id=" + id + ", access time=" + idMap.get(id));
                }
            }
            int[] affectedRecords = pStmt.executeBatch();
            long success = 0;
            long noInfo = 0;
            long failed = 0;
            long unknown = 0;
            for(int i =0; i < affectedRecords.length; i++){
                int current = affectedRecords[i];
                switch(current){
                    case Statement.SUCCESS_NO_INFO:
                        noInfo++;
                        break;
                        case Statement.EXECUTE_FAILED:
                            failed++;
                            break;
                    default:
                        if(current<0){
                            unknown += current;
                        }else {
                            success += current;
                        }
                        break;
                }
            }
            DebugUtil.trace(this, "updated last_accessed:" +
                    "\n   attempted : " + affectedRecords.length +
                    "\n          ok : " + success +
                    "\n ok, no info : " + noInfo +
                    "\n     unknown : " + unknown +
                    "\n      failed : " + failed);
            releaseConnection(cr);

        } catch (SQLException sqlException) {
            destroyConnection(cr);
            throw new GeneralException("Unable to set last time:" + sqlException.getMessage());
        }

    }


    @Override
    public V get(Object o) {
        V v = super.get(o);
        listeningStore.fireLastAccessedEvent(this, (Identifier) o);
        return v;
    }

    public UpkeepConfiguration getUpkeepConfiguration() {
        return upkeepConfiguration;
    }

    @Override
    public void setUpkeepConfiguration(UpkeepConfiguration upkeepConfiguration) {
        this.upkeepConfiguration = upkeepConfiguration;
    }

    UpkeepConfiguration upkeepConfiguration;

    @Override
    public UpkeepResponse doUpkeep(AbstractEnvironment environment) {
        return null;
    }

    @Override
    public long updateHook(String action, AbstractEnvironment environment, List<Identifier> identifiers) {
        return 0L;
    }
}
