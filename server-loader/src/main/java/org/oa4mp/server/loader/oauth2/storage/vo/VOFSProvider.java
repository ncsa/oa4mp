package org.oa4mp.server.loader.oauth2.storage.vo;

import org.oa4mp.server.api.OA4MPConfigTags;
import edu.uiuc.ncsa.security.storage.FSProvider;
import org.apache.commons.configuration.tree.ConfigurationNode;

import java.io.File;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/14/20 at  1:14 PM
 */
public class VOFSProvider<T extends VIFileStore> extends FSProvider<T> implements OA4MPConfigTags {
    public VOFSProvider(ConfigurationNode config,
                        VOProvider provider,
                        VIConverter converter) {
        super(config, FILE_STORE, VIRTUAL_ORGANIZATION_STORE, converter);
        this.provider = provider;
    }

    VOProvider provider = null;


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
