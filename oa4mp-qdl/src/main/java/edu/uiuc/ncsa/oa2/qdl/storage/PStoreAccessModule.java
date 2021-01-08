package edu.uiuc.ncsa.oa2.qdl.storage;

import edu.uiuc.ncsa.qdl.extensions.QDLFunction;
import edu.uiuc.ncsa.qdl.module.Module;
import edu.uiuc.ncsa.qdl.state.State;

import java.net.URI;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/23/20 at  8:48 AM
 */
public class PStoreAccessModule extends StoreAccessModule {
    public PStoreAccessModule() {
        System.out.println("in pstore SAM constructor");
    }

    public PStoreAccessModule(URI namespace, String alias) {
        super(namespace, alias);
    }

    @Override
    public Module newInstance(State state) {
        PStoreAccessModule storeAccessModule = new PStoreAccessModule(URI.create("oa2:/qdl/p_store"), "p_store");
        storeAccessModule.storeFacade = newStoreFacade();
        doIt(storeAccessModule, state);
        return storeAccessModule;
    }

    @Override
    public StoreFacade newStoreFacade() {
        return new PermissionStoreFacade();
    }

    @Override
    protected List<QDLFunction> createFList(StoreFacade sf) {
        List<QDLFunction> functions = super.createFList(sf);
        PermissionStoreFacade permissionStoreFacade = (PermissionStoreFacade) sf;
        functions.add(permissionStoreFacade.new ClientCount());
        functions.add(permissionStoreFacade.new GetAdmins());
        functions.add(permissionStoreFacade.new GetClients());
        return functions;
    }
}
