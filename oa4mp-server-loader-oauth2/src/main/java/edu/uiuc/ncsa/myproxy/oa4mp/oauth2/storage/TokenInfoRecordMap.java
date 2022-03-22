package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage;

import edu.uiuc.ncsa.security.core.Identifier;

import java.util.*;

/**
 * This tracks {@link TokenInfoRecord} by their client and transaction id, since we need
 * to manage them both ways. This is intended to be used by the token info endpoint
 * to accumulate
 * <p>Created by Jeff Gaynor<br>
 * on 3/21/22 at  8:28 AM
 */
public class TokenInfoRecordMap {
    Map<Identifier, List<TokenInfoRecord>> tMap = new HashMap<>();
    Map<Identifier, List<TokenInfoRecord>> cMap = new HashMap<>();

    public void put(TokenInfoRecord tir) {
        if (contains(tir)) {
            return;
         }

        put(tMap, tir, tir.transactionID);
        put(cMap, tir, tir.clientID);
    }

    protected void put(Map<Identifier, List<TokenInfoRecord>> map, TokenInfoRecord tir, Identifier identifier) {
        List<TokenInfoRecord> list;
        if (!map.containsKey(identifier)) {
            list = new ArrayList<>();
            map.put(identifier, list);
        } else {
            list = map.get(identifier);
        }
        list.add(tir);

    }

    /**
     * For a given transaction id, get all of the token records.
     *
     * @param transactionID
     * @return
     */
    public List<TokenInfoRecord> getByTID(Identifier transactionID) {
        return tMap.get(transactionID);
    }

    /**
     * Get all of the token records associated with this client id. You must
     * separate them out by transaction id.
     *
     * @param clientID
     * @return
     */
    public List<TokenInfoRecord> getByClientID(Identifier clientID) {
        return cMap.get(clientID);
    }

    public boolean contains(TokenInfoRecord tir) {
        if (!tMap.containsKey(tir.transactionID)) {
            return false;
        }
        List<TokenInfoRecord> list = tMap.get(tir.transactionID);
        for (TokenInfoRecord tokenInfoRecord : list) {
            if (tir.hasAccessToken()) {
                if (tir.accessToken.equals(tokenInfoRecord.accessToken)) {
                    return true;
                }
            }
            if (tir.hasRefreshToken()) {
                if (tir.refreshToken.equals(tokenInfoRecord.refreshToken)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Returns <code>true</code> if this client has a {@link TokenInfoRecord}.
     *
     * @param clientID
     * @return
     */
    public boolean containsClient(Identifier clientID) {
        return cMap.containsKey(clientID);
    }

    /**
     * get the set of all client ids
     *
     * @return
     */
    public Set<Identifier> getClientIDs() {
        return cMap.keySet();
    }

    /**
     * Gets the set of all transaction ids.
     *
     * @return
     */
    public Set<Identifier> getTransactionIDs() {
        return tMap.keySet();
    }

    /**
     * Given the transaction id, find the corresponding token id.
     *
     * @param tID
     * @return
     */
    public Identifier getClientID(Identifier tID) {
        List<TokenInfoRecord> tirs = tMap.get(tID);
        if (tirs == null || tirs.isEmpty()) {
            return null;
        }
        // all of these should have the same client ID
        return tirs.get(0).clientID;
    }

    /**
     * removes all the token info records associated with this client.
     *
     * @param clientID
     */
    public void remove(Identifier clientID) {
        List<TokenInfoRecord> list = cMap.get(clientID);
        cMap.remove(clientID);
        for (TokenInfoRecord tir : list) {
            tMap.remove(tir.transactionID);
        }
    }

    /**
     * Remove all identifiers <b><i>except</i></b> the ones in the list
     *
     * @param clientIDs
     */
    public void reduceTo(Set<Identifier> clientIDs) {
        if (clientIDs == null || clientIDs.isEmpty()) {
            return;
        }
        for (Identifier id : clientIDs) {
            remove(id);
        }
    }

    /**
     * returns a map of all tokens associated with the transaction id. The key is the
     * transaction ID.
     *
     * @param clientID
     * @return
     */
    public Map<Identifier, List<TokenInfoRecord>> sortByClientID(Identifier clientID) {
        List<TokenInfoRecord> r = cMap.get(clientID);
        Map<Identifier, List<TokenInfoRecord>> map = new HashMap<>();
        for (TokenInfoRecord tir : r) {
            List<TokenInfoRecord> list;
            if (map.containsKey(tir.transactionID)) {
                list = map.get(tir.transactionID);
            } else {
                list = new ArrayList<>();
                map.put(tir.transactionID, list);
            }
            list.add(tir);
        }
        return map;
    }

}

