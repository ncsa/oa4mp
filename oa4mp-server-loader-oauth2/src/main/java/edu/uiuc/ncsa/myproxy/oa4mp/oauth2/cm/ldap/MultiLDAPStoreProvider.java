package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.ldap;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.configuration.provider.MultiTypeProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/22/16 at  4:26 PM
 */
public class MultiLDAPStoreProvider<V extends LDAPEntry> extends MultiTypeProvider<LDAPStore<V>> {

    public MultiLDAPStoreProvider(ConfigurationNode config,
                                  boolean disableDefaultStore,
                                  MyLoggingFacade logger,
                                  String type,
                                  String target,
                                  IdentifiableProvider<V> tp) {
        super(config, disableDefaultStore, logger, type, target);
        ldapEntryProvider= tp;
    }


    // public class MultiDSPermissionStoreProvider<V extends Permission> extends MultiTypeProvider<PermissionsStore<V>> {

    IdentifiableProvider<V> ldapEntryProvider;

    @Override
    public LDAPStore<V> getDefaultStore() {
        logger.info("Getting default LDAP configuration store");
        return new LDAPMemoryStore<>(ldapEntryProvider);
    }
}
