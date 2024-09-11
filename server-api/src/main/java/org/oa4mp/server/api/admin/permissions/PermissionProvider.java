package org.oa4mp.server.api.admin.permissions;

import org.oa4mp.server.api.admin.transactions.OA4MPIdentifierProvider;
import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/11/16 at  11:25 AM
 */
public class PermissionProvider<V extends Permission> extends IdentifiableProviderImpl<V> {
    public PermissionProvider() {
        super(new OA4MPIdentifierProvider(OA4MPIdentifierProvider.PERMISSION_ID));
    }

    @Override
    public V get(boolean createNewIdentifier) {
        return (V) new Permission(createNewId(createNewIdentifier));
    }
}
