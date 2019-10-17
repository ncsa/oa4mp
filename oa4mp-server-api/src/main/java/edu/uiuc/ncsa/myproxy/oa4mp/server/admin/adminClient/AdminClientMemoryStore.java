package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.XMLConverter;
import edu.uiuc.ncsa.security.storage.MemoryStore;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.util.Date;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/20/16 at  12:48 PM
 */
public class AdminClientMemoryStore<V extends AdminClient> extends MemoryStore<V> implements AdminClientStore<V> {
    public AdminClientMemoryStore(IdentifiableProvider<V> identifiableProvider) {
        super(identifiableProvider);
        acProvider = identifiableProvider;
        acConverter = new AdminClientConverter<>(new AdminClientKeys(), identifiableProvider);
    }
    public IdentifiableProvider<V> acProvider = null;
      public AdminClientConverter<V> acConverter = null;

    @Override
    public XMLConverter<V> getXMLConverter() {
        return acConverter;
    }
    public MapConverter<V> getMapConverter() {
        return acConverter;
    }

    @Override
    public IdentifiableProvider getACProvider() {
        return acProvider;
    }

    @Override
    protected void realSave(V value) {
        value.setLastModifiedTS(new java.sql.Timestamp(new Date().getTime()));
        super.realSave(value);
    }
}
