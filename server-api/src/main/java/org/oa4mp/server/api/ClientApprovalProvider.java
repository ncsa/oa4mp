package org.oa4mp.server.api;

import org.oa4mp.server.api.admin.transactions.OA4MPIdentifierProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;
import edu.uiuc.ncsa.security.core.util.IdentifierProvider;
import org.oa4mp.delegation.server.storage.ClientApproval;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/4/12 at  4:21 PM
 */
public class ClientApprovalProvider extends IdentifiableProviderImpl<ClientApproval> {
    public ClientApprovalProvider(IdentifierProvider<Identifier> idProvider) {
        super(idProvider);
    }

    public ClientApprovalProvider() {
        super(new OA4MPIdentifierProvider(OA4MPIdentifierProvider.CLIENT_APPROVAL_ID));
    }

    @Override
    public ClientApproval get(boolean createNewIdentifier) {
        return new ClientApproval(createNewId(createNewIdentifier));
    }
}
