package edu.uiuc.ncsa.oa2.qdl.storage;

import edu.uiuc.ncsa.qdl.extensions.JavaModule;
import edu.uiuc.ncsa.qdl.extensions.QDLFunction;
import edu.uiuc.ncsa.qdl.extensions.QDLVariable;
import edu.uiuc.ncsa.qdl.module.Module;
import edu.uiuc.ncsa.qdl.state.State;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/18/20 at  3:09 PM
 */
public class StoreAccessModule extends JavaModule {
    public StoreAccessModule() {
    }

    public StoreAccessModule(URI namespace, String alias) {
        super(namespace, alias);
    }

    /**
     * Override this wil the module and store. Then call {@link #doIt(StoreAccessModule, StoreFacade, State)}
     * to finish off the setup.
     *
     * @param state
     * @return
     */
    @Override
    public Module newInstance(State state) {
        StoreAccessModule storeAccessModule = new StoreAccessModule(URI.create("oa2:/qdl/store"), "store");
        StoreFacade configuredStoreFacade = new StoreFacade();
        doIt(storeAccessModule, configuredStoreFacade, state);
        return storeAccessModule;
    }

    /**
     * This sets up the module.
     *
     * @param storeAccessModule
     * @param storeFacade
     * @param state
     */
    protected void doIt(StoreAccessModule storeAccessModule, StoreFacade storeFacade, State state) {
        if (state != null) {
            storeFacade.setLogger(state.getLogger());
        }
        storeAccessModule.addFunctions(createFList(storeFacade));
        storeAccessModule.addVariables(createVarList(storeFacade));

    }

    protected List<QDLVariable> createVarList(StoreFacade configuredStoreFacade) {
        List<QDLVariable> vars = new ArrayList<>();
        vars.add(configuredStoreFacade.new FacadeHelp());
        vars.add(configuredStoreFacade.new StoreTypes());
        return vars;
    }

    protected List<QDLFunction> createFList(StoreFacade configuredStoreFacade) {
        List<QDLFunction> functions = new ArrayList<>();
        functions.add(configuredStoreFacade.new Create());
        functions.add(configuredStoreFacade.new FromXML());
        functions.add(configuredStoreFacade.new InitMethod());
        functions.add(configuredStoreFacade.new Keys());
        functions.add(configuredStoreFacade.new ReadObject());
        functions.add(configuredStoreFacade.new Remove());
        functions.add(configuredStoreFacade.new Search());
        functions.add(configuredStoreFacade.new Size());
        functions.add(configuredStoreFacade.new SaveObject());
        functions.add(configuredStoreFacade.new ToXML());
        return functions;
    }
}
