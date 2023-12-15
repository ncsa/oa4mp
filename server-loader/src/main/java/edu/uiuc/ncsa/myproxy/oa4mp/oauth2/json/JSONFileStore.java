package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.json;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.storage.FileStore;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.util.json.JSONEntry;
import edu.uiuc.ncsa.security.util.json.JSONStore;

import java.io.File;
import java.util.Date;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/20/19 at  10:13 AM
 */
public class JSONFileStore<V extends JSONEntry> extends FileStore<V> implements JSONStore<V> {
    @Override
    public List<V> getMostRecent(int n, List<String> attributes) {
        throw new UnsupportedOperationException();
    }

    public JSONFileStore(File storeDirectory,
                         File indexDirectory,
                         IdentifiableProvider<V> identifiableProvider,
                         MapConverter<V> converter, boolean removeEmptyFiles, boolean removeFailedFiles) {
        super(storeDirectory, indexDirectory, identifiableProvider, converter, removeEmptyFiles,removeFailedFiles);
    }

    @Override
    public void realSave(boolean checkExists, V t) {
        t.setLastModified(new Date());
        super.realSave(checkExists, t);
    }
}
