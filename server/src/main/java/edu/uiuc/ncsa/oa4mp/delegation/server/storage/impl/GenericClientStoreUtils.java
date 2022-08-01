package edu.uiuc.ncsa.oa4mp.delegation.server.storage.impl;

import edu.uiuc.ncsa.oa4mp.delegation.server.storage.BaseClientStore;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.ClientApprovalKeys;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.XMLConverter;
import edu.uiuc.ncsa.security.storage.GenericStoreUtils;
import edu.uiuc.ncsa.security.storage.XMLMap;

import java.util.ArrayList;
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

}
