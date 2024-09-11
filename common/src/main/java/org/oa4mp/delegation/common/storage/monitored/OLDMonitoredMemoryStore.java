package org.oa4mp.delegation.common.storage.monitored;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.storage.MonitoredStoreDelegate;
import edu.uiuc.ncsa.security.storage.MonitoredStoreInterface;
import edu.uiuc.ncsa.security.storage.MemoryStore;
import edu.uiuc.ncsa.security.storage.monitored.Monitored;
import edu.uiuc.ncsa.security.storage.events.IDMap;
import edu.uiuc.ncsa.security.storage.events.LastAccessedEventListener;
import edu.uiuc.ncsa.security.storage.monitored.upkeep.UpkeepConfiguration;

import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/29/23 at  12:43 PM
 * @deprecated use {@link edu.uiuc.ncsa.security.storage.monitored.MonitoredMemoryStore} in Sec-Lib
 */
public abstract class OLDMonitoredMemoryStore<V extends Identifiable> extends MemoryStore<V> implements MonitoredStoreInterface<V> {
    public OLDMonitoredMemoryStore(IdentifiableProvider<V> identifiableProvider) {
        super(identifiableProvider);
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
    public void fireLastAccessedEvent(MonitoredStoreInterface store,Identifier identifier) {
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
    @Override
    public void lastAccessUpdate(IDMap idMap) {
        for (Identifier id : idMap.keySet()) {
             V v = super.get(id); // use super or a last accessed time event gets fired.
             Monitored monitored = (Monitored)v;
             if(monitored.getLastAccessed().getTime() < idMap.get(id)){
                 ((Monitored) v).setLastAccessed(new Date(idMap.get(id)));
                 save(v);
             }
         }
    }

    @Override
    public V get(Object key) {
        V v =super.get(key);
        fireLastAccessedEvent(this, (Identifier) key);
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
}

