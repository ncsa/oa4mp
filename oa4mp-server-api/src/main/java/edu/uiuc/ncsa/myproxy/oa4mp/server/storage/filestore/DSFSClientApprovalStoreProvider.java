package edu.uiuc.ncsa.myproxy.oa4mp.server.storage.filestore;

import edu.uiuc.ncsa.myproxy.oa4mp.server.ClientApprovalProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.ClientApproverConverter;
import edu.uiuc.ncsa.security.storage.FSProvider;
import org.apache.commons.configuration.tree.ConfigurationNode;

import java.io.File;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/18/12 at  3:12 PM
 */
public class DSFSClientApprovalStoreProvider extends FSProvider<DSFSClientApprovalStore> implements OA4MPConfigTags {


    public DSFSClientApprovalStoreProvider(ConfigurationNode config, ClientApproverConverter clientApproverConverter) {
        super(config, FILE_STORE, CLIENT_APPROVAL_STORE, clientApproverConverter);
    }

    @Override
    protected DSFSClientApprovalStore produce(File dataPath, File indexPath) {
        return new DSFSClientApprovalStore(dataPath, indexPath, new ClientApprovalProvider(), converter);
    }
}
