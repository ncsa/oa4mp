package org.oa4mp.server.loader.oauth2.storage.keys;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.XMLConverter;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.storage.GenericStoreUtils;
import edu.uiuc.ncsa.security.storage.MemoryStore;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import org.oa4mp.server.loader.oauth2.storage.vi.VirtualIssuer;

import java.util.HashSet;
import java.util.List;
import java.util.Map;

public class KEMemoryStore<V extends KERecord> extends MemoryStore<V> implements KEStore<V> {
    public KEMemoryStore(IdentifiableProvider<V> identifiableProvider, KEConverter<V> converter) {
        super(identifiableProvider);
        this.converter = converter;
    }

    KEConverter<V> converter;
    @Override
    public XMLConverter<V> getXMLConverter() {
        return converter;
    }

    @Override
    public List<V> getMostRecent(int n, List<String> attributes) {
        return GenericStoreUtils.getMostRecent(this, n, attributes);
    }

    @Override
    public KERecord getByKID(String kid) {
        return KEStoreUtilities.getByKID(this, kid);
    }
    @Override
    public HashSet<String> getKIDs() {
        return KEStoreUtilities.getKIDs(this);
    }

    @Override
    public JSONWebKeys getCurrentKeys(VirtualIssuer vi) {
        return null;
    }

    @Override
    public JSONWebKeys getCurrentKeys() {
        return null;
    }

    @Override
    public Map<Identifier, KERecord> getByVI(VirtualIssuer vi) {
        throw new NotImplementedException();
    }
}
