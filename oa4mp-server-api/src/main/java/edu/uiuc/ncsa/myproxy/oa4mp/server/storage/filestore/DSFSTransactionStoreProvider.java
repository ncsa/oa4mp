package edu.uiuc.ncsa.myproxy.oa4mp.server.storage.filestore;

import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;
import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.TransactionConverter;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.configuration.provider.CfgEvent;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.storage.FSProvider;
import org.apache.commons.configuration.tree.ConfigurationNode;

import javax.inject.Provider;
import java.io.File;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/16/12 at  4:24 PM
 */
public class DSFSTransactionStoreProvider<T extends DSFSTransactionStore> extends FSProvider<T> implements OA4MPConfigTags {
    public DSFSTransactionStoreProvider(ConfigurationNode config,
                                        IdentifiableProvider<? extends OA4MPServiceTransaction> tp,
                                        Provider<TokenForge> tfp,
                                        TransactionConverter<? extends OA4MPServiceTransaction> tc
                                        ) {
        super(config, FILE_STORE, TRANSACTIONS_STORE, tc);
        this.transactionProvider = tp;
        this.tokenForgeProvider = tfp;
    }

    protected IdentifiableProvider<? extends OA4MPServiceTransaction> transactionProvider;
    protected Provider<TokenForge> tokenForgeProvider;

    @Override
    public Object componentFound(CfgEvent configurationEvent) {
        if (checkEvent(configurationEvent)) {
            return super.componentFound(configurationEvent);
        }
        return null;
    }

    @Override
    protected T produce(File dataPath, File indexPath) {
        return (T) new DSFSTransactionStore(dataPath, indexPath, transactionProvider, tokenForgeProvider.get(), converter);
    }
}
