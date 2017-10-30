package org.scitokens.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.DSTransactionProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.OA4MPIdentifierProvider;
import org.scitokens.util.STTransaction;
import org.scitokens.util.STTransactionConverter;
import org.scitokens.util.STTransactionKeys;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifierProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import org.apache.commons.configuration.tree.ConfigurationNode;

import javax.inject.Provider;

import static edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.OA4MPIdentifierProvider.TRANSACTION_ID;
import static edu.uiuc.ncsa.security.core.util.IdentifierProvider.SCHEME;
import static edu.uiuc.ncsa.security.core.util.IdentifierProvider.SCHEME_SPECIFIC_PART;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/25/17 at  11:15 AM
 */
public class STLoader extends OA2ConfigurationLoader {
    public STLoader(ConfigurationNode node) {
        super(node);
    }

    public STLoader(ConfigurationNode node, MyLoggingFacade logger) {
        super(node, logger);
    }

    public static class STTProvider extends DSTransactionProvider<STTransaction> {

         public STTProvider(IdentifierProvider<Identifier> idProvider) {
             super(idProvider);
         }

         @Override
         public STTransaction get(boolean createNewIdentifier) {
             return new STTransaction(createNewId(createNewIdentifier));
         }
     }

    @Override
    protected Provider<TransactionStore> getTSP() {
        STTProvider tp = new STTProvider(new OA4MPIdentifierProvider(SCHEME, SCHEME_SPECIFIC_PART, TRANSACTION_ID, false));
        STTransactionKeys keys = new STTransactionKeys();
        STTransactionConverter<STTransaction> tc = new STTransactionConverter<STTransaction>(keys,
                tp,
                (TokenForge)getTokenForgeProvider().get(),
                (ClientStore)getClientStoreProvider().get());
        return getTSP(tp, tc);
    }
}
