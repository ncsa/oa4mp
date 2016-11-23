package edu.uiuc.ncsa.co.ldap;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.storage.MemoryStore;

import java.util.HashMap;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/22/16 at  3:20 PM
 */
public class LDAPMemoryStore<V extends LDAPEntry> extends MemoryStore<V> implements LDAPStore<V>{
    public LDAPMemoryStore(IdentifiableProvider<V> identifiableProvider) {
        super(identifiableProvider);
    }
    HashMap<Identifier, LDAPEntry> clientIDMap = new HashMap<>();

    @Override
    public void clear() {
        clientIDMap = new HashMap<>();
        super.clear();
    }

    @Override
    public LDAPEntry getByClientID(Identifier clientID) {
        return clientIDMap.get(clientID);
    }

    @Override
    public V put(Identifier key, V value) {
        if(clientIDMap.containsKey(value.getClientID())){
            clientIDMap.remove(value.getClientID());
        }
        clientIDMap.put(value.getClientID(),value);
        return super.put(key, value);
    }

    @Override
    public V remove(Object key) {
        LDAPEntry x = get(key);
        if(x!= null){
            clientIDMap.remove(x.getClientID());
        }
        return super.remove(key);
    }
}
