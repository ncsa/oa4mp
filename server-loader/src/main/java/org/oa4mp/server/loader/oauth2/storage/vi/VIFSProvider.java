package org.oa4mp.server.loader.oauth2.storage.vi;

import edu.uiuc.ncsa.security.core.cf.CFNode;
import edu.uiuc.ncsa.security.storage.FSProvider;
import org.oa4mp.server.api.OA4MPConfigTags;

import java.io.File;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/14/20 at  1:14 PM
 */
public class VIFSProvider<T extends VIFileStore> extends FSProvider<T> implements OA4MPConfigTags {

    public VIFSProvider(CFNode config,
                        VIProvider provider,
                        VIConverter converter) {
        super(config, FILE_STORE, VIRTUAL_ORGANIZATION_STORE, converter);
        this.provider = provider;
    }

    VIProvider provider = null;


    @Override
    protected T produce(File dataPath, File indexPath, boolean removeEmptyFiles, boolean removeFailedFiles) {
        return (T) new VIFileStore(dataPath,
                indexPath,
                provider,
                converter,
                removeEmptyFiles,
                removeFailedFiles);

    }
}
