package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.vo;

import edu.uiuc.ncsa.security.core.XMLConverter;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.storage.MemoryStore;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.util.HashMap;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/14/20 at  10:37 AM
 */
public class VOMemoryStore<V extends VirtualOrganization> extends MemoryStore<V> implements VOStore<V> {
    public VOMemoryStore(VOProvider<V> identifiableProvider,
                         VOConverter<V> converter) {
        super(identifiableProvider);
        this.converter = converter;
    }

    VOConverter<V> converter;

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
        value.setLastModified(System.currentTimeMillis());
        super.save(value);
        updateIndices(value);
    }

    @Override
    public void update(V value) {
        value.setLastModified(System.currentTimeMillis());
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
}
