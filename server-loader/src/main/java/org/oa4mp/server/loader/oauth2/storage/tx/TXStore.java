package org.oa4mp.server.loader.oauth2.storage.tx;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/14/20 at  8:54 AM
 */
public interface TXStore<V extends TXRecord> extends Store<V> {
    public MapConverter<V> getMapConverter();

    /**
     * Get a list of all records for a given parent.
     * @param parentID
     * @return
     */
    List<V> getByParentID(Identifier parentID);

    int getCountByParent(Identifier parentID);
}
