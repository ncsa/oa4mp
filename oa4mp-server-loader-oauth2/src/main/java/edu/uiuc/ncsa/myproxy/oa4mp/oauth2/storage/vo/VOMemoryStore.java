package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.vo;

import edu.uiuc.ncsa.security.core.XMLConverter;
import edu.uiuc.ncsa.security.storage.MemoryStore;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

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
}
