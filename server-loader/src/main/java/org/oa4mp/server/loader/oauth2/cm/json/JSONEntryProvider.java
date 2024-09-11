package org.oa4mp.server.loader.oauth2.cm.json;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;
import edu.uiuc.ncsa.security.util.json.JSONEntry;

import javax.inject.Provider;
import java.util.Date;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/20/19 at  11:40 AM
 */
public class JSONEntryProvider<V extends JSONEntry> extends IdentifiableProviderImpl<V> {
    public JSONEntryProvider(Provider<Identifier> idProvider) {
        super(idProvider);
    }
     /*
        protected V newClient(boolean createNewIdentifier){
        return (V) new Client(createNewId(createNewIdentifier));
    }
    @Override
    public V get(boolean createNewIdentifier) {
        V v = newClient(createNewIdentifier);
        v.setCreationTS(new Date());
        return v;
    }
      */
     protected V createnewEntry(boolean createNewIdentifier){
         return (V) new JSONEntry(createNewId(createNewIdentifier));
     }
    @Override
    public V get(boolean createNewIdentifier) {
        V v= createnewEntry(createNewIdentifier);
        v.setCreationTimestamp(new Date());
        return v;
    }
}
