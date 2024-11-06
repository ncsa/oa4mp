package org.oa4mp.server.loader.oauth2.storage.vi;

import edu.uiuc.ncsa.security.core.XMLConverter;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.storage.GenericStoreUtils;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.monitored.MonitoredMemoryStore;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/14/20 at  10:37 AM
 */
public class VIMemoryStore<V extends VirtualIssuer> extends MonitoredMemoryStore<V> implements VIStore<V> {
    public VIMemoryStore(VIProvider<V> identifiableProvider,
                         VIConverter<V> converter) {
        super(identifiableProvider);
        this.converter = converter;
    }

    VIConverter<V> converter;

    @Override
    public XMLConverter<V> getXMLConverter() {
        return converter;
    }

    @Override
    public MapConverter<V> getMapConverter() {
        return converter;
    }

    @Override
    public V findByPath(String component) {
        return pathIndex.get(component);
    }

    Map<String, V> pathIndex = new HashMap<>();

    protected void updateIndices(V v) {
        if (!StringUtils.isTrivial(v.getDiscoveryPath())) {
            pathIndex.put(v.getDiscoveryPath(), v);
        }
    }

    protected void removeIndex(V value) {
        if (!StringUtils.isTrivial(value.getDiscoveryPath())) {
            pathIndex.remove(value.getDiscoveryPath());
        }
    }

    @Override
    public void register(V value) {
        super.register(value);
        updateIndices(value);
    }

    @Override
    public void save(V value) {
        value.setLastModifiedTS(new Date());
        super.save(value);
        updateIndices(value);
    }

    @Override
    public void update(V value) {
        value.setLastModifiedTS(new Date());
        super.update(value);
        updateIndices(value);
    }

    @Override
    public void clear() {
        super.clear();
        clearIndices();
    }

    protected void clearIndices() {
        pathIndex = new HashMap<>();
    }

    @Override
    public V remove(Object key) {
        V item = super.remove(key);
        if (item != null) {
            removeIndex(item);
        }
        return item;
    }

    @Override
    public List<V> getMostRecent(int n, List<String> attributes) {
        return GenericStoreUtils.getMostRecent(this, n, attributes);
    }
}
