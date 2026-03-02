package org.oa4mp.server.loader.oauth2.storage.keys;

import edu.uiuc.ncsa.security.core.cf.CFNode;
import edu.uiuc.ncsa.security.storage.FSProvider;
import org.oa4mp.server.api.OA4MPConfigTags;

import java.io.File;

public class KEFSProvider<T extends KEFileStore> extends FSProvider<T> implements OA4MPConfigTags {
    public KEFSProvider(String target, KEConverter converter, KERecordProvider keRecordProvider) {
        super(FILE_STORE, target, converter);
        this.keRecordProvider = keRecordProvider;
    }

    public KEFSProvider(CFNode config,  KEConverter converter, KERecordProvider keRecordProvider) {
        super(config, FILE_STORE, KEY_STORE, converter);
        this.keRecordProvider = keRecordProvider;
    }

    KERecordProvider keRecordProvider;
    @Override
    protected T produce(File dataPath, File indexPath, boolean removeEmptyFiles, boolean removeFailedFiles) {
        return (T) new KEFileStore<>(dataPath,
                indexPath, keRecordProvider, converter, removeEmptyFiles,removeFailedFiles);
    }
}
