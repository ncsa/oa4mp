package edu.uiuc.ncsa.oa4mp.delegation.server.storage;

import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.Client;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

/**
 * Marker interface for client stores
 * <p>Created by Jeff Gaynor<br>
 * on May 24, 2011 at  4:02:39 PM
 */
public interface ClientStore<V extends Client> extends BaseClientStore<V> {
        public MapConverter<V> getMapConverter();
}
