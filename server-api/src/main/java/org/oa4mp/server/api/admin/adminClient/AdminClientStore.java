package org.oa4mp.server.api.admin.adminClient;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import org.oa4mp.delegation.server.storage.BaseClientStore;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/12/16 at  1:20 PM
 */
public interface AdminClientStore<V extends AdminClient> extends BaseClientStore<V> {
    public MapConverter<V> getMapConverter();
}