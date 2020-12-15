package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx;

import edu.uiuc.ncsa.security.core.XMLConverter;
import edu.uiuc.ncsa.security.storage.MemoryStore;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/14/20 at  10:37 AM
 */
public class TXMemoryStore<V extends TXRecord> extends MemoryStore<V> implements TXStore<V>{
    public TXMemoryStore(TXRecordProvider<V> identifiableProvider,
                         TXRecordConverter<V> converter) {
        super(identifiableProvider);
        this.converter = converter;
    }
    TXRecordConverter<V> converter;

    @Override
    public XMLConverter<V> getXMLConverter() {
        return converter;
    }

    @Override
    public MapConverter<V> getMapConverter() {
        return converter;
    }
}
