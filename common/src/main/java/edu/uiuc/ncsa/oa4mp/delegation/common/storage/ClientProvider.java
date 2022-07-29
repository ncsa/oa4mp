package edu.uiuc.ncsa.oa4mp.delegation.common.storage;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;
import edu.uiuc.ncsa.security.core.util.IdentifierProvider;

import java.util.Date;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/4/12 at  2:54 PM
 */
public class ClientProvider<V extends Client> extends IdentifiableProviderImpl<V> {

    public ClientProvider(IdentifierProvider<Identifier> idProvider) {
        super(idProvider);
    }

    /**
     * Override this to return a different client. The {@link #get(boolean)} method calls this.
     * @param createNewIdentifier
     * @return
     */
    protected V newClient(boolean createNewIdentifier){
        return (V) new Client(createNewId(createNewIdentifier));
    }
    @Override
    public V get(boolean createNewIdentifier) {
        V v = newClient(createNewIdentifier);
        v.setCreationTS(new Date());
        return v;
    }

}
