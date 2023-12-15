package edu.uiuc.ncsa.oa4mp.delegation.server.storage.impl;

import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.Client;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.monitored.MonitoredFileStore;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.io.File;
import java.util.Date;
import java.util.List;

/**
 * File-based storage for clients.
 * <p>Created by Jeff Gaynor<br>
 * on 11/3/11 at  3:40 PM
 */
//public abstract class FSClientStore<V extends Client> extends FileStore<V> implements ClientStore<V> {
public abstract class FSClientStore<V extends Client> extends MonitoredFileStore<V> implements ClientStore<V> {
    protected FSClientStore(File storeDirectory, File indexDirectory, IdentifiableProviderImpl<V> idp,MapConverter<V> cp,
                            boolean removeEmptyFiles, boolean removeFailedFiles) {
        super(storeDirectory, indexDirectory, idp, cp, removeEmptyFiles, removeFailedFiles);
    }

    public FSClientStore(File f, IdentifiableProviderImpl<V> idp,MapConverter<V> cp, boolean removeEmptyFiles, boolean removeFailedFiles) {
        super(f, idp, cp, removeEmptyFiles,removeFailedFiles);
    }

    @Override
    public MapConverter<V> getMapConverter() {
        return converter;
    }

    @Override
    public void realSave(boolean checkExists, V t) {
        t.setLastModifiedTS(new java.sql.Timestamp(new Date().getTime()));
        super.realSave(checkExists, t);
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
