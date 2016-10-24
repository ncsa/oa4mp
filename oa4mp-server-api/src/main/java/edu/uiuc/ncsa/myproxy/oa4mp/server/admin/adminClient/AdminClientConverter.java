package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.delegation.storage.impl.BaseClientConverter;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/20/16 at  1:17 PM
 */
public class AdminClientConverter<V extends AdminClient> extends BaseClientConverter<V>{
    public AdminClientConverter(SerializationKeys keys, IdentifiableProvider<V> provider) {
        super(keys, provider);
    }
    // At this point no need to override to/from map.
}
