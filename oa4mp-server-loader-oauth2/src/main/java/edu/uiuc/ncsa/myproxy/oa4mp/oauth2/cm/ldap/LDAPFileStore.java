package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.ldap;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.storage.FileStore;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.io.File;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/22/16 at  3:29 PM
 */
public class LDAPFileStore<V extends LDAPEntry> extends FileStore<V> implements LDAPStore<V> {
    public LDAPFileStore(File directory, IdentifiableProvider<V> idp, MapConverter<V> cp) {
        super(directory, idp, cp);
    }

    public LDAPFileStore(File storeDirectory, File indexDirectory, IdentifiableProvider<V> identifiableProvider, MapConverter<V> converter) {
        super(storeDirectory, indexDirectory, identifiableProvider, converter);
    }

    @Override
    public LDAPEntry getByClientID(Identifier clientID) {
        for(LDAPEntry entry : values()){
            if(entry.getClientID().equals(clientID)){
                return entry;
            }
        }
        return null;
    }
}
