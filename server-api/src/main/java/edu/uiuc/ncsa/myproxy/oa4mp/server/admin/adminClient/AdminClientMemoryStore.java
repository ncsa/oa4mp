package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient;

import edu.uiuc.ncsa.oa4mp.delegation.server.storage.uuc.UUCResponse;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.uuc.UUCConfiguration;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.XMLConverter;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.impl.GenericClientStoreUtils;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.storage.GenericStoreUtils;
import edu.uiuc.ncsa.security.storage.MemoryStore;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.util.Date;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/20/16 at  12:48 PM
 */
public class AdminClientMemoryStore<V extends AdminClient> extends MemoryStore<V> implements AdminClientStore<V> {
    public AdminClientMemoryStore(IdentifiableProvider<V> identifiableProvider) {
        super(identifiableProvider);
        acProvider = identifiableProvider;
        acConverter = new AdminClientConverter<>(new AdminClientKeys(), identifiableProvider);
    }
    public IdentifiableProvider<V> acProvider = null;
      public AdminClientConverter<V> acConverter = null;

    @Override
    public XMLConverter<V> getXMLConverter() {
        return acConverter;
    }
    public MapConverter<V> getMapConverter() {
        return acConverter;
    }


    @Override
    protected void realSave(V value) {
        value.setLastModifiedTS(new java.sql.Timestamp(new Date().getTime()));
        super.realSave(value);
    }

    @Override
    public List<Identifier> getByStatus(String status, ClientApprovalStore clientApprovalStore) {
        return GenericClientStoreUtils.getByStatus(this, status, clientApprovalStore);
    }

    @Override
    public List<Identifier> getByApprover(String approver, ClientApprovalStore clientApprovalStore) {
        return GenericClientStoreUtils.getByApprover(this, approver, clientApprovalStore);
    }

    @Override
    public List<V> getMostRecent(int n, List<String> attributes) {
        return GenericStoreUtils.getMostRecent(this, n, attributes);
    }

    @Override
    public UUCResponse unusedClientCleanup(UUCConfiguration uucConfiguration) {
        throw new NotImplementedException();
    }
}
