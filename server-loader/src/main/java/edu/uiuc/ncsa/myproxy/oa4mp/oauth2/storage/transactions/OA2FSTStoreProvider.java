package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.transactions;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.DSFSTransactionStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.TransactionConverter;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.TokenForge;
import org.apache.commons.configuration.tree.ConfigurationNode;

import javax.inject.Provider;
import java.io.File;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/25/14 at  12:15 PM
 */
public class OA2FSTStoreProvider<T extends OA2FSTStore> extends DSFSTransactionStoreProvider<T> {
    public OA2FSTStoreProvider(ConfigurationNode config,
                               IdentifiableProvider<? extends OA2ServiceTransaction> tp,
                               Provider<TokenForge> tfp,
                               TransactionConverter<? extends OA2ServiceTransaction> tc) {
        super(config, tp, tfp, tc);
    }

    @Override
    protected T produce(File dataPath, File indexPath, boolean removeEmptyFiles) {
        return (T) new OA2FSTStore<>(dataPath, indexPath, (IdentifiableProvider<? extends OA2ServiceTransaction>) transactionProvider, tokenForgeProvider.get(), converter, removeEmptyFiles);
    }

}
