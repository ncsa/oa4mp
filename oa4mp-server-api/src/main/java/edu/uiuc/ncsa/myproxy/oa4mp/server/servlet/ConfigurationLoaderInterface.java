package edu.uiuc.ncsa.myproxy.oa4mp.server.servlet;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.delegation.server.issuers.AGIssuer;
import edu.uiuc.ncsa.security.delegation.server.issuers.ATIssuer;
import edu.uiuc.ncsa.security.delegation.server.issuers.PAIssuer;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;

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
