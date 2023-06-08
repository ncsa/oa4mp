package edu.uiuc.ncsa.oa4mp.delegation.common.storage.transactions;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AccessToken;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AuthorizationGrant;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.TokenForge;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.Verifier;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.AuthorizationGrantImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.VerifierImpl;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;

import java.net.URI;

/**
 * A map converter bridging the gap between the interface and the backing store.
 * <p>Created by Jeff Gaynor<br>
 * on 4/13/12 at  3:08 PM
 */
public class BasicTransactionConverter<V extends BasicTransaction> extends MapConverter<V> {
    public TokenForge getTokenForge() {
        return tokenForge;
    }

    protected TokenForge tokenForge;

    protected BasicTransactionKeys getBTKeys() {
        return (BasicTransactionKeys) keys;
    }

    public BasicTransactionConverter(IdentifiableProvider<V> identifiableProvider, TokenForge tokenForge) {
        this(new BasicTransactionKeys(), identifiableProvider, tokenForge);

    }

    public BasicTransactionConverter(SerializationKeys keys, IdentifiableProvider<V> identifiableProvider, TokenForge tokenForge) {
        super(keys, identifiableProvider);
        this.tokenForge = tokenForge;
    }

    @Override
    public V fromMap(ConversionMap<String, Object> data, V v) {
        BasicTransaction b = super.fromMap(data, v); // this sets the temp token
        // save it for later since it is derived from the auth grant and if that is not set, there may be
        // contention over the value later. The id never changes.
        Identifier id = b.getIdentifier();
        Object token = data.get(getBTKeys().authGrant());
        if (token == null) {
            b.setAuthorizationGrant(null);
        }else{
            if (token instanceof AuthorizationGrant) {
                b.setAuthorizationGrant((AuthorizationGrant) token);
            } else {
                b.setAuthorizationGrant(new AuthorizationGrantImpl(URI.create(token.toString())));
            }
        }

        token = data.get(getBTKeys().accessToken());
        if (token == null) {
            b.setAccessToken(null);
        }else{
            if (token instanceof AccessToken) {
                b.setAccessToken((AccessToken) token);
            } else {
                AccessTokenImpl at = new AccessTokenImpl(URI.create(token.toString()));
                b.setAccessToken(at);
            }
        }



        token = data.get(getBTKeys().verifier());
        if (token != null) {
            if (token instanceof Verifier) {
                b.setVerifier((Verifier) token);
            } else {
                VerifierImpl verifier = new VerifierImpl(URI.create(token.toString()));
                b.setVerifier(verifier);
            }
        }
        b.setIdentifier(id);  // Make sure it is right!

        return (V) b;
    }

    @Override
    public void toMap(V value, ConversionMap<String, Object> data) {
        super.toMap(value, data);
        if (value.hasAuthorizationGrant()) {
            data.put(getBTKeys().authGrant(), value.getAuthorizationGrant().getToken());
        }
        if (value.hasAccessToken()) {
            data.put(getBTKeys().accessToken(), value.getAccessToken().getJti().toString());
        }
        if (value.hasVerifier()) {
            data.put(getBTKeys().verifier(), value.getVerifier().getToken());
        }
    }
}
