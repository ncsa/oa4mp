package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.storage.MemoryStore;

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
    public AdminClientConverter getACConverter() {
        return acConverter;
    }

    @Override
    public IdentifiableProvider getACProvider() {
        return acProvider;
    }
}
