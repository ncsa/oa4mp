package org.oa4mp.delegation.server.storage.impl;

import org.oa4mp.delegation.common.storage.clients.Client;
import org.oa4mp.delegation.common.storage.clients.ClientConverter;
import org.oa4mp.delegation.server.storage.ClientApprovalStore;
import org.oa4mp.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.XMLConverter;
import edu.uiuc.ncsa.security.storage.GenericStoreUtils;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.monitored.MonitoredMemoryStore;

import java.util.Date;
import java.util.List;

/**  Abstract class that gets the inheritance and generics right.
 * <p>Created by Jeff Gaynor<br>
 * on 1/18/12 at  11:12 AM
 */
public  class ClientMemoryStore<V extends Client> extends MonitoredMemoryStore<V> implements ClientStore<V> {
    @Override
    public List<V> getMostRecent(int n, List<String> attributes) {
        return GenericStoreUtils.getMostRecent(this, n, attributes);
    }

    public ClientMemoryStore(IdentifiableProvider<V> vIdentifiableProvider) {
        super(vIdentifiableProvider);
    }

    @Override
    public XMLConverter<V> getXMLConverter() {
        return getMapConverter();
    }
    public MapConverter<V> getMapConverter() {
        return new ClientConverter(this.identifiableProvider);
    }


    @Override
    public void save(V value) {
        value.setLastModifiedTS(new java.sql.Timestamp(new Date().getTime()));
        super.save(value);
    }

    @Override
    public List<Identifier> getByStatus(String status, ClientApprovalStore clientApprovalStore) {
        return GenericClientStoreUtils.getByStatus(this, status, clientApprovalStore);
    }

    @Override
    public List<Identifier> getByApprover(String approver, ClientApprovalStore clientApprovalStore) {
        return GenericClientStoreUtils.getByApprover(this, approver, clientApprovalStore);
    }
}
