package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.configuration.provider.MultiTypeProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/19/16 at  11:12 AM
 */
public class MultiDSPermissionStoreProvider<V extends Permission> extends MultiTypeProvider<PermissionsStore<V>> {
    public MultiDSPermissionStoreProvider(ConfigurationNode config,
                                          boolean disableDefaultStore,
                                          MyLoggingFacade logger,
                                          String type,
                                          String target,
                                          IdentifiableProvider<V> tp) {
        super(config, disableDefaultStore, logger, type, target);
        permissionProvider = tp;
    }

    IdentifiableProvider<V> permissionProvider;

    @Override
    public PermissionsStore<V> getDefaultStore() {
        logger.info("Using default in memory permission store.");
        return new MemoryPermissionStore<>(permissionProvider);
    }
}
