package edu.uiuc.ncsa.oa4mp.delegation.common.storage;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.XMLConverter;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.transactions.BasicTransaction;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AccessToken;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AuthorizationGrant;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.Verifier;
import edu.uiuc.ncsa.security.storage.AggregateStore;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

/**
 * An aggregate store for transactions.
 * <p>Created by Jeff Gaynor<br>
 * on 5/24/12 at  11:19 AM
 */
public class AggregateTransactionStore<V extends TransactionStore> extends AggregateStore<V> implements TransactionStore {
    public AggregateTransactionStore(V... stores) {
        super(stores);
    }

    @Override
    public BasicTransaction get(AccessToken accessToken) {
        BasicTransaction t = null;
        for(TransactionStore s: stores){
           t = s.get(accessToken);
            if(t != null) return t;
        }
        return null;
    }



    @Override
    public BasicTransaction getByProxyID(Identifier proxyID) {
        BasicTransaction t = null;
        for(TransactionStore s: stores){
           t = s.getByProxyID(proxyID);
            if(t != null) return t;
        }
        return null;
    }

    @Override
    public BasicTransaction get(AuthorizationGrant authorizationGrant) {
        BasicTransaction t = null;
        for(TransactionStore s: stores){
           t = s.get(authorizationGrant);
            if(t != null) return t;
        }
        return null;
    }

    @Override
    public BasicTransaction get(Verifier verifier) {
        BasicTransaction t = null;
        for(TransactionStore s: stores){
           t = s.get(verifier);
            if(t != null) return t;
        }
        return null;
    }

    @Override
    public XMLConverter getXMLConverter() {
        throw new NotImplementedException(" there is no single converter possible for an aggregate store. Method not implemented");
    }

    @Override
    public MapConverter getMapConverter() {
        throw new NotImplementedException(" there is no single converter possible for an aggregate store. Method not implemented");
    }
}
