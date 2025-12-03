package org.oa4mp.server.api.storage.filestore;

import edu.uiuc.ncsa.security.core.cf.CFNode;
import edu.uiuc.ncsa.security.storage.FSProvider;
import org.oa4mp.server.api.ClientApprovalProvider;
import org.oa4mp.server.api.OA4MPConfigTags;
import org.oa4mp.server.api.util.ClientApproverConverter;

import java.io.File;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/18/12 at  3:12 PM
 */
public class DSFSClientApprovalStoreProvider extends FSProvider<DSFSClientApprovalStore> implements OA4MPConfigTags {
    public DSFSClientApprovalStoreProvider(CFNode config, ClientApproverConverter clientApproverConverter) {
        super(config, FILE_STORE, CLIENT_APPROVAL_STORE, clientApproverConverter);
    }

    @Override
    protected DSFSClientApprovalStore produce(File dataPath, File indexPath, boolean removeEmptyFiles, boolean removeFailedFiles) {
        return new DSFSClientApprovalStore(dataPath, indexPath, new ClientApprovalProvider(), converter, removeEmptyFiles, removeFailedFiles);
    }
}
