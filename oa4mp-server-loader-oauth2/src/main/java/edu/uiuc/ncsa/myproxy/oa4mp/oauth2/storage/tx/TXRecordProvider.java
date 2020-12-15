package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;
import edu.uiuc.ncsa.security.oauth_2_0.OA2TokenForge;

import javax.inject.Provider;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/14/20 at  10:43 AM
 */
public class TXRecordProvider<V extends TXRecord> extends IdentifiableProviderImpl<V> {
    public TXRecordProvider(Provider<Identifier> idProvider, OA2TokenForge tokenForge) {
        super(idProvider);
        this.tokenForge = tokenForge;
    }


    OA2TokenForge tokenForge;

    @Override
    public V get(boolean createNewIdentifier) {
        V txr = (V) new TXRecord(BasicIdentifier.newID(tokenForge.getAuthorizationGrant().getToken()));
        return txr;
    }
}
