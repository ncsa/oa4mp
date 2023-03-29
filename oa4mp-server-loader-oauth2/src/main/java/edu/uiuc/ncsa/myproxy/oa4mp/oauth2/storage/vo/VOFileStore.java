package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.vo;

import edu.uiuc.ncsa.oa4mp.delegation.common.storage.monitored.MonitoredFileStore;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.storage.GenericStoreUtils;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.io.File;
import java.io.IOException;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/14/20 at  9:02 AM
 */
public class VOFileStore<V extends VirtualOrganization> extends MonitoredFileStore<V> implements VOStore<V> {
    public VOFileStore(File storeDirectory,
                       File indexDirectory,
                       IdentifiableProvider<V> identifiableProvider,
                       MapConverter<V> converter,
                       boolean removeEmptyFiles) {
        super(storeDirectory, indexDirectory, identifiableProvider, converter, removeEmptyFiles);
    }

    public VOFileStore(File directory,
                       IdentifiableProvider<V> idp,
                       MapConverter<V> cp,
                       boolean removeEmptyFiles) {
        super(directory, idp, cp, removeEmptyFiles);
    }

    @Override
    public MapConverter<V> getMapConverter() {
        return converter;
    }

    @Override
    public V findByPath(String component) {
        return getIndexEntry(component);
    }

    @Override
    protected V realRemove(V oldItem) {
        super.realRemove(oldItem);
        if (!StringUtils.isTrivial(oldItem.getDiscoveryPath())) {
            removeIndexEntry(oldItem.getDiscoveryPath());
        }
        return oldItem;
    }

    @Override
    public void realSave(boolean checkExists, V t) {
        t.setLastModified(System.currentTimeMillis());
        super.realSave(checkExists, t);
        try {
            if (!StringUtils.isTrivial(t.getDiscoveryPath())) {
                createIndexEntry(t.getDiscoveryPath(), t.getIdentifierString());
            }
        } catch (IOException e) {
            throw new GeneralException("Error serializing item " + t + "to file ");
        }
    }

    @Override
    public List<V> getMostRecent(int n, List<String> attributes) {
        return GenericStoreUtils.getMostRecent(this, n, attributes);
    }
}
