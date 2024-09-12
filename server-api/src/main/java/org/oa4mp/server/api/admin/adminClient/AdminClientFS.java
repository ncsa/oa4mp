package org.oa4mp.server.api.admin.adminClient;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import org.oa4mp.delegation.server.storage.ClientApprovalStore;
import org.oa4mp.delegation.server.storage.impl.GenericClientStoreUtils;
import edu.uiuc.ncsa.security.storage.FileStore;
import edu.uiuc.ncsa.security.storage.GenericStoreUtils;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.io.File;
import java.util.Date;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/20/16 at  12:51 PM
 */
public class AdminClientFS<V extends AdminClient> extends FileStore<V> implements AdminClientStore<V> {
    public AdminClientFS(File directory,
                         IdentifiableProvider<V> idp,
                         MapConverter<V> cp,
                         boolean removeEmptyFiles,
                         boolean removeFailedFiles) {
        super(directory, idp, cp, removeEmptyFiles,removeFailedFiles);
    }

    public AdminClientFS(File storeDirectory,
                         File indexDirectory,
                         IdentifiableProvider<V> identifiableProvider,
                         MapConverter<V> converter,
                         boolean removeEmptyFiles,
                         boolean removeFailedFiles) {
        super(storeDirectory, indexDirectory, identifiableProvider, converter, removeEmptyFiles,removeFailedFiles);

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

    @Override
    public List<V> getMostRecent(int n, List<String> attributes) {
        return GenericStoreUtils.getMostRecent(this, n, attributes);
    }

 /*   @Override
    public UUCResponse unusedClientCleanup(UUCConfiguration uucConfiguration) {
        throw new NotImplementedException();
    }*/
}
