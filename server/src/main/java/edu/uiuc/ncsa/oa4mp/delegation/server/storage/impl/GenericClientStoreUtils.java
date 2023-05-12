package edu.uiuc.ncsa.oa4mp.delegation.server.storage.impl;

import edu.uiuc.ncsa.oa4mp.delegation.common.storage.BaseClient;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.ClientApprovalKeys;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.BaseClientStore;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.uuc.UUCConfiguration;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.uuc.UUCRetentionPolicy;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.XMLConverter;
import edu.uiuc.ncsa.security.storage.GenericStoreUtils;
import edu.uiuc.ncsa.security.storage.XMLMap;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 8/10/21 at  9:41 AM
 */
public class GenericClientStoreUtils extends GenericStoreUtils {
    /**
     * Emulates a let outer join for generic stores.
     *
     * @param store
     * @param fieldName
     * @param field
     * @param caStore
     * @return
     */
    protected static List<Identifier> getByField(BaseClientStore store,
                                                 String fieldName,
                                                 String field,
                                                 ClientApprovalStore caStore) {
        List<Identifier> returnedValues = new ArrayList<>();
        XMLMap map;

        XMLConverter caConverter = caStore.getXMLConverter();
        for (Object obj : caStore.values()) {
            ClientApproval ca = (ClientApproval) obj;
            map = new XMLMap();
            caConverter.toMap(ca, map);
            if (map.containsKey(fieldName)) {
                if (map.get(fieldName).equals(field)) {
                    if (store.containsKey(ca.getIdentifier())) {
                        returnedValues.add(ca.getIdentifier());
                    }
                }
            }
        }
        return returnedValues;
    }

    public static List<Identifier> getByStatus(BaseClientStore store,
                                               String status,
                                               ClientApprovalStore caStore) {
        ClientApprovalKeys caKeys = (ClientApprovalKeys) caStore.getMapConverter().getKeys();
        return getByField(store, caKeys.status(), status, caStore);
    }

    public static List<Identifier> getByApprover(BaseClientStore store,
                                                 String approver,
                                                 ClientApprovalStore caStore) {
        ClientApprovalKeys caKeys = (ClientApprovalKeys) caStore.getMapConverter().getKeys();
        return getByField(store, caKeys.approver(), approver, caStore);
    }

    public static BaseClientStore.UUCResponse unusedClientCleanup(BaseClientStore store, UUCConfiguration uucConfiguration) {
        UUCRetentionPolicy uucRetentionPolicy = new UUCRetentionPolicy(store, uucConfiguration);
        BaseClientStore.UUCResponse response = new BaseClientStore.UUCResponse();
        int total = 0;
        int processed = 0;
        int skipped = 0;
        List<String> foundIds = new ArrayList<>();
        for (Object obj : store.values()) {
            BaseClient baseClient = (BaseClient) obj;
            if(!acceptLADate(uucConfiguration, baseClient.getLastAccessed())){
                continue;
            }
/*
            if(baseClient.getLastAccessed() != null && baseClient.getLastAccessed().getTime() != 0L){
                continue;
            }
*/
            total++;
            if (uucRetentionPolicy.retain(baseClient.getIdentifier(), baseClient.getCreationTS().getTime(), baseClient.getLastModifiedTS().getTime())) {
                // do nothing for now.
                skipped++;
            }else{
                processed++;
                if (uucConfiguration.testMode) {
                    foundIds.add(baseClient.getIdentifierString());
                } else {
                    store.remove(baseClient.getIdentifier());
                }
            }
        }
        response.found = foundIds;
        response.success = processed;
        response.total = total;
        response.skipped = skipped;
        return response;
    }

    /**
     * If the date complies with the configuration. So a true means to process this entry.
     * @param uucConfiguration
     * @param lastAccessed
     * @return
     */
    protected static boolean acceptLADate(UUCConfiguration uucConfiguration, Date lastAccessed){
        if(uucConfiguration.unusedClientsOnly()){
            return lastAccessed==null || lastAccessed.getTime()==0;
        }
        // in the sequel, never used means it was not used before a date, nor between two dates,
        // so the proper response is to return false.
        if(lastAccessed==null || lastAccessed.getTime()==0) return false;
        long la = lastAccessed.getTime();
        if(uucConfiguration.hasLastAccessedAfter()){
            // so look for a date between
            return uucConfiguration.lastAccessedAfter<=la && la <= uucConfiguration.lastAccessed;

        }else{
            // only dates before last accessed
            return  la <= uucConfiguration.lastAccessed;
        }
    }
}
