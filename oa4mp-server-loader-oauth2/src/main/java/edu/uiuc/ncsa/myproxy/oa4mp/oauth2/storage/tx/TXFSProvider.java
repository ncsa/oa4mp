package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx;

import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;
import edu.uiuc.ncsa.security.oauth_2_0.OA2TokenForge;
import edu.uiuc.ncsa.security.storage.FSProvider;
import org.apache.commons.configuration.tree.ConfigurationNode;

import java.io.File;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/14/20 at  1:14 PM
 */
public class TXFSProvider<T extends TXFileStore> extends FSProvider<T> implements OA4MPConfigTags {
    public TXFSProvider(ConfigurationNode config,
                        TXRecordProvider provider,
                        TXRecordConverter converter) {
        super(config, FILE_STORE, TOKEN_EXCHANGE_RECORD_STORE, converter);
        this.provider = provider;
    }

    TXRecordProvider provider = null;
    OA2TokenForge tokenForge = null;


    @Override
    protected T produce(File dataPath, File indexPath, boolean removeEmptyFiles) {
        return (T) new TXFileStore(dataPath,
                indexPath,
                provider,
                converter,
                removeEmptyFiles);

    }
}
