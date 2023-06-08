package edu.uiuc.ncsa.oa4mp.delegation.common.storage.transactions;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.XMLConverter;
import edu.uiuc.ncsa.security.core.cache.CachedMapFacade;
import edu.uiuc.ncsa.security.core.exceptions.DestroyedException;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.core.exceptions.UnregisteredObjectException;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.TransactionStore;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AccessToken;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AuthorizationGrant;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.Verifier;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.net.URI;
import java.util.*;

/**
 * A cache. Set the backing store if you have one, otherwise this works perfectly well as an
 * in-memory store.
 * <h3>Usage</h3>
 * To front a transaction store, write the store separately then instantiate an instance of this, passing
 * the frontend store as an argument. You may then use the store and all it's facilities (such as retention policies)
 * as you see fit.
 * <p>Created by Jeff Gaynor<br>
 * on Apr 27, 2010 at  4:27:10 PM
 */
public class TransactionCache<V extends BasicTransaction> extends CachedMapFacade<V> implements TransactionStore<V> {
    @Override
    public List<V> getMostRecent(int n, List<String> attributes) {
        return null;
    }

    public TransactionStore getBackingStore() {
        return (TransactionStore) getTheStore();
    }

    @Override
    public XMLConverter<V> getXMLConverter() {
        return getBackingStore().getXMLConverter();
    }

    public TransactionCache(TransactionStore backingStore) {
        super(backingStore);
        init();
    }

    public TransactionIndices getTransactionIndices() {
        if (transactionIndices == null) {
            transactionIndices = new TransactionIndices();
        }
        return transactionIndices;
    }

    TransactionIndices transactionIndices;

    public AbstractEnvironment getEnvironment() {
        return environment;
    }

    public void setEnvironment(AbstractEnvironment environment) {
        this.environment = environment;
    }

    AbstractEnvironment environment;

    public TransactionCache() {
        super();
        init();
    }

    public boolean isDestroyed() {
        return destroyed;
    }

    protected void setDestroyed(boolean destroyed) {
        this.destroyed = destroyed;
    }

    boolean destroyed = true;

    public boolean destroy() {
        setDestroyed(true);
        getTransactionIndices().clear();
        getCache().clear();
        if (hasStore()) {
            getTheStore().clear();
        }
        return false;
    }

    public boolean init() {
        setDestroyed(false);
        getTransactionIndices().clear();
        getCache().clear();
        // don't touch backing store here
        return true;
    }

    public void put(V t) {
        checkDestroyed();
        getTransactionIndices().add(t);
        getCache().add(t);
    }

    protected void checkDestroyed() {
        if (isDestroyed()) {
            throw new DestroyedException();
        }
    }

    @Override
    public int size(boolean includeVersions) {
        throw new NotImplementedException("Internal error: A cache should never call this.");
    }

    @Override
    public List<V> getAll() {
        throw new NotImplementedException("Error: this is not supported in a cache.");
    }

    public void update(BasicTransaction t) {
        if (t == null) {
            throw new GeneralException("Error: null transaction cannot be updated");
        }
        checkDestroyed();
        if (!containsKey(t.getIdentifier())) {
            throw new UnregisteredObjectException("Error: non-existent transaction \"" + t.getIdentifierString() + "\" cannot be updated. Save it first.");
        }
        getTransactionIndices().updateIndices(t);
        getTransactionIndices().add(t);
        getCache().add(t);
        if (hasStore()) getBackingStore().update(t);
    }


    final int TEMP_CRED = 0;
    final int ACCESS_TOKEN = 1;
    final int VERIFIER = 2;
    final int IDENTIFIER = 3;

    /**
     * This is done as a switch statement to keep references to the cache up to date.
     *
     * @param key
     * @param action
     * @return
     */
    protected V getByKey(Object key, int action) {
        checkDestroyed();
        BasicTransaction t = null;
        switch (action) {
            case TEMP_CRED:
                t = getTransactionIndices().get((AuthorizationGrant) key);
                break;
            case ACCESS_TOKEN:
                t = getTransactionIndices().get((AccessToken) key);
                break;
            case VERIFIER:
                t = getTransactionIndices().get((Verifier) key);
                break;
            case IDENTIFIER:
                t = getTransactionIndices().get((Identifier) key);
                break;
            default:
                throw new IllegalStateException("Error: unrecognized action for getting a transaction");
        }
        if (t != null) return (V) t;
        if (hasStore()) {
            switch (action) {
                case TEMP_CRED:
                    t = getBackingStore().get((AuthorizationGrant) key);
                    break;
                case ACCESS_TOKEN:
                    t = getBackingStore().get((AccessToken) key);
                    break;
                case VERIFIER:
                    t = getBackingStore().get((Verifier) key);
                    break;
                case IDENTIFIER:
                    t = (BasicTransaction) getBackingStore().get(key);
                    break;

            }
            if (t != null) {
                getTransactionIndices().add(t);
            }
        }
        return (V) t;
    }


    public V get(AuthorizationGrant tempCred) {
        return getByKey(tempCred, TEMP_CRED);
    }

    public V get(AccessToken accessToken) {
        return getByKey(accessToken, ACCESS_TOKEN);
    }

    public V get(Verifier verifier) {
        return getByKey(verifier, VERIFIER);
    }


    public int size() {
        checkDestroyed();
        return super.size();
    }

    public boolean isEmpty() {
        checkDestroyed();
        return super.isEmpty();
    }

    public boolean containsKey(Object key) {
        checkDestroyed();
        return super.containsKey(key);
    }

    public boolean containsValue(Object value) {
        checkDestroyed();
        return super.containsValue(value);
    }

    public V get(Object key) {
        return super.get(key);
        //return getByKey(key, IDENTIFIER);
    }


    public BasicTransaction remove(URI identifier) {
        checkDestroyed();
        getTransactionIndices().remove(identifier.toString());
        return super.remove(identifier.toString());
    }


    public V create() {
        checkDestroyed();
        if (hasStore()) {
            return (V) getBackingStore().create();
        }
        return (V) new BasicTransaction((Identifier) null);
    }


    public V put(Identifier key, V value) {
        checkDestroyed();
        getTransactionIndices().add(value);
        return super.put(key, value);
    }
    /*
    A bit of confusion here because of Java. The key parameters for the class is a String, but the signature must be an object.
    The interface requires a remove(String), return a boolean, while the collection API requires that it return a
    transaction (no multiple return types in Java...).  So this call returns a transaction, the remove(String) call
    returns a boolean.

     */

    public V remove(Object key) {
        checkDestroyed();
        BasicTransaction t = getTransactionIndices().remove(key);
        // NOTE that super removes it from the cache too.
        return super.remove(key);
    }


    public void putAll(Map m) {
        checkDestroyed();
        super.putAll(m);
    }

    public void clear() {
        checkDestroyed();
        getTransactionIndices().clear();
        super.clear();
    }

    public Set<Identifier> keySet() {
        checkDestroyed();
        return super.keySet();
    }

    public Collection<V> values() {
        checkDestroyed();
        return super.values();
    }

    public Set<Entry<Identifier, V>> entrySet() {
        checkDestroyed();
        return super.entrySet();
    }

    public void save(V t) {
        checkDestroyed();
        put(t);
        if (hasStore()) {
            getBackingStore().save(t);
        }
    }


    public BasicTransaction remove(BasicTransaction t) {
        return remove(t.getIdentifierString());
    }

    public void register(V transaction) {
        put(transaction);
    }

    @Override
    public String toString() {
        return "TransactionCache[" + getCache().size() + " elements, " + (hasStore() ? "has a" : "no") + " store]";
    }

    /**
     * The indices for a transaction store. This allows managing retrieval by identifier, tempCred, access token
     * or verifier.
     * <br>This does not implement map since this is to be an aggregate of indices, even though this behaves like a map
     * in many ways. Forcing it to be one is not a clean separation of concerns. For instance, the transaction has its
     * identifier embedded in it, so the key/value pair operations are redundant.
     * <p>Created by Jeff Gaynor<br>
     * on Nov 22, 2010 at  11:51:33 AM
     */
    public static class TransactionIndices<V extends BasicTransaction> {
        /**
         * A list of transactions that have been created but not saved. Multiple create requests must
         * return the same instance of a transaction.
         *
         * @return
         */
        public HashMap<Identifier, V> getCreatedTransactions() {
            if (createdTransactions == null) {
                createdTransactions = new HashMap<Identifier, V>();
            }
            return createdTransactions;
        }


        HashMap<Identifier, V> createdTransactions;

        public void add(V t) {
            getTransactions().put(t.getIdentifier(), t);
            getCreatedTransactions().remove(t.getIdentifier());
            updateIndices(t);
        }

        public void remove(V t) {
            getTransactions().remove(t.getIdentifierString());
            removeFromIndices(t);
        }

        protected Map<Identifier, V> getTransactions() {
            if (transactions == null) {
                transactions = new HashMap<Identifier, V>();
            }
            return transactions;
        }

        public V get(Identifier identifier) {
            return getTransactions().get(identifier);
        }

        public V get(AuthorizationGrant authorizationGrant) {
            if (!getAuthorizationGrantIndex().containsKey(authorizationGrant.getToken())) {
                return null;
            }
            return get(getAuthorizationGrantIndex().get(authorizationGrant.getToken()));
        }

        public V get(AccessToken accessToken) {
            if (!getAccessTokenIndex().containsKey(accessToken.getToken())) {
                return null;
            }
            return get(getAccessTokenIndex().get(accessToken.getToken()));
        }

        public V get(Verifier verifier) {
            if (!getVerifierIndex().containsKey(verifier.getToken())) {
                return null;
            }
            return get(getVerifierIndex().get(verifier.getToken()));
        }


        HashMap<Identifier, V> transactions;

        public void clear() {
            transactions = null;
            verifierIndex = null;
            accessTokenIndex = null;
            AuthorizationGrantIndex = null;
            createdTransactions = null;
        }

        public int size() {
            return getTransactions().size();
        }

        public boolean isEmpty() {
            return getTransactions().isEmpty();
        }

        public boolean containsKey(Object key) {
            return getTransactions().containsKey(key);
        }

        public boolean containsValue(Object value) {
            return getTransactions().containsValue(value);
        }


        public V put(Identifier key, V value) {
            V oldT = get(key);
            add(value);
            return oldT;
        }

        public V remove(Object key) {
            V oldT = getTransactions().remove(key);
            if (oldT != null) {
                // might not have one.

                removeFromIndices(oldT);
            }
            return oldT;
        }

        public void putAll(Map<? extends String, ? extends BasicTransaction> m) {
            for (BasicTransaction t : m.values()) {
                add((V) t);
            }
        }

        public Set<Identifier> keySet() {
            return getTransactions().keySet();
        }

        public Collection<V> values() {
            return getTransactions().values();
        }


        public Set<Entry<Identifier, V>> entrySet() {
            return getTransactions().entrySet();
        }


        HashMap<String, Identifier> AuthorizationGrantIndex;
        HashMap<String, Identifier> verifierIndex;

        protected HashMap<String, Identifier> getAuthorizationGrantIndex() {
            if (AuthorizationGrantIndex == null) {
                AuthorizationGrantIndex = new HashMap<String, Identifier>();
            }
            return AuthorizationGrantIndex;
        }


        protected HashMap<String, Identifier> getVerifierIndex() {
            if (verifierIndex == null) {
                verifierIndex = new HashMap<String, Identifier>();
            }
            return verifierIndex;
        }

        protected HashMap<String, Identifier> getAccessTokenIndex() {
            if (accessTokenIndex == null) {
                accessTokenIndex = new HashMap<String, Identifier>();
            }
            return accessTokenIndex;
        }

        HashMap<String, Identifier> accessTokenIndex;

        protected void updateIndices(BasicTransaction t) {
            if (t.hasAccessToken()) {
                getAccessTokenIndex().put(t.getAccessToken().getToken(), t.getIdentifier());
            }
            if (t.hasAuthorizationGrant()) {
                getAuthorizationGrantIndex().put(t.getAuthorizationGrant().getToken(), t.getIdentifier());
            }
            if (t.hasVerifier()) {
                getVerifierIndex().put(t.getVerifier().getToken(), t.getIdentifier());
            }
        }


        protected void removeFromIndices(BasicTransaction t) {
            if (t.hasAccessToken()) {
                getAccessTokenIndex().remove(t.getAccessToken().getToken());
            }
            if (t.hasAuthorizationGrant()) {
                getAuthorizationGrantIndex().remove(t.getAuthorizationGrant().getToken());
            }
            if (t.hasVerifier()) {
                getVerifierIndex().remove(t.getVerifier().getToken());
            }
        }
    }

    @Override
    public List<V> search(String key, String condition, boolean isRegEx) {
        throw new NotImplementedException("Error: This is not yet implemented for cache");
    }

    @Override
    public List<V> search(String key, String condition, boolean isRegEx, List<String> attr) {
        throw new NotImplementedException("Error: This is not yet implemented for cache");
    }

    @Override
    public List<V> search(String key, String condition, boolean isRegEx, List<String> attr, String dateField, Date before, Date after) {
        throw new NotImplementedException("Error: This is not yet implemented for cache");
    }


    @Override
    public MapConverter getMapConverter() {
        throw new NotImplementedException("Error: This is not yet implemented for cache");
    }

    @Override
    public boolean remove(List<Identifiable> objects) {
        throw new NotImplementedException("Error: This is not yet implemented for cache");
    }

    @Override
    public V getByProxyID(Identifier proxyID) {
        throw new NotImplementedException("Error: This is not yet implemented for cache");
    }
}
