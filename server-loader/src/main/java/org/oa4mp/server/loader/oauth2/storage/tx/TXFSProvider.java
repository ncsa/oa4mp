package org.oa4mp.server.loader.oauth2.storage.tx;

import edu.uiuc.ncsa.security.core.cf.CFNode;
import edu.uiuc.ncsa.security.storage.FSProvider;
import org.oa4mp.server.api.OA4MPConfigTags;

import java.io.File;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/14/20 at  1:14 PM
 */
public class TXFSProvider<T extends TXFileStore> extends FSProvider<T> implements OA4MPConfigTags {

    public TXFSProvider(CFNode config,
                        TXRecordProvider provider,
                        TXRecordConverter converter) {
        super(config, FILE_STORE, TOKEN_EXCHANGE_RECORD_STORE, converter);
        this.provider = provider;
    }

    TXRecordProvider provider = null;


    @Override
    protected T produce(File dataPath, File indexPath, boolean removeEmptyFiles, boolean removeFailedFiles) {
        return (T) new TXFileStore(dataPath,
                indexPath,
                provider,
                converter,
                removeEmptyFiles,
                removeFailedFiles);

    }
}
