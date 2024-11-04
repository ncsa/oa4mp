package org.oa4mp.server.loader.oauth2.storage.vo;

import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/14/20 at  8:54 AM
 */
public interface VIStore<V extends VirtualIssuer> extends Store<V> {
     MapConverter<V> getMapConverter();

    V findByPath(String component);
}
