package org.oa4mp.server.api.storage.servlet;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import org.oa4mp.delegation.server.issuers.AGIssuer;
import org.oa4mp.delegation.server.issuers.ATIssuer;
import org.oa4mp.delegation.server.issuers.PAIssuer;
import org.oa4mp.delegation.server.storage.ClientApprovalStore;
import org.oa4mp.delegation.server.storage.ClientStore;
import org.oa4mp.delegation.common.storage.clients.Client;
import org.oa4mp.delegation.common.storage.TransactionStore;
import org.oa4mp.delegation.common.token.TokenForge;

import javax.inject.Provider;
import java.util.HashMap;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/26/15 at  4:01 PM
 */
public interface ConfigurationLoaderInterface {
    Provider<ClientStore> getClientStoreProvider();

    Provider<ClientApprovalStore> getClientApprovalStoreProvider();

    Provider<TransactionStore> getTransactionStoreProvider();

    Provider<TokenForge> getTokenForgeProvider();

    Provider<AGIssuer> getAGIProvider();

    Provider<ATIssuer> getATIProvider();

    Provider<PAIssuer> getPAIProvider();

    HashMap<String, String> getConstants();

    IdentifiableProvider<? extends Client> getClientProvider();
}
