package edu.uiuc.ncsa.oa4mp.delegation.common.storage.monitored;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.storage.AbstractListeningStore;
import edu.uiuc.ncsa.security.storage.FileStore;
import edu.uiuc.ncsa.security.storage.ListeningStoreInterface;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.data.Monitored;
import edu.uiuc.ncsa.security.storage.events.IDMap;
import edu.uiuc.ncsa.security.storage.events.LastAccessedEventListener;

import java.io.File;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/29/23 at  10:00 AM
 */
public abstract class MonitoredFileStore<V extends Identifiable> extends FileStore<V> implements ListeningStoreInterface<V> {
    public MonitoredFileStore(File storeDirectory,
                              File indexDirectory,
                              IdentifiableProvider<V> identifiableProvider,
                              MapConverter<V> converter,
                              boolean removeEmptyFiles,
                              boolean removeFailedFiles) {
        super(storeDirectory, indexDirectory, identifiableProvider, converter, removeEmptyFiles,removeFailedFiles);
    }

    public MonitoredFileStore(File directory, IdentifiableProvider<V> idp, MapConverter<V> cp, boolean removeEmptyFiles,
                              boolean removeFailedFiles) {
        super(directory, idp, cp, removeEmptyFiles,removeFailedFiles);
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
    public void fireLastAccessedEvent(ListeningStoreInterface store, Identifier identifier) {
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
            long lastAccessed = idMap.get(id);
            V v = super.get(id); // use super or a last accessed time event gets fired.
            Monitored monitored = (Monitored)v;
            if(monitored.getLastAccessed().getTime()<lastAccessed){
                ((Monitored) v).setLastAccessed(new Date(lastAccessed));
                save(v);
            }
        }
    }

    @Override
    public V get(Object key) {
        V v = super.get(key);
        listeningStore.fireLastAccessedEvent(this,(Identifier) key);
        return v;
    }
}
