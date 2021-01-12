package edu.uiuc.ncsa.oa2.qdl.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.qdl.evaluate.ControlEvaluator;
import edu.uiuc.ncsa.qdl.exceptions.QDLException;
import edu.uiuc.ncsa.qdl.extensions.QDLFunction;
import edu.uiuc.ncsa.qdl.extensions.QDLVariable;
import edu.uiuc.ncsa.qdl.state.State;
import edu.uiuc.ncsa.qdl.variables.StemVariable;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.util.configuration.ConfigUtil;
import org.apache.commons.configuration.tree.ConfigurationNode;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import static edu.uiuc.ncsa.security.core.util.StringUtils.isTrivial;

/**
 * The class with the inner classes that do all the work here.
 * <p>Created by Jeff Gaynor<br>
 * on 12/18/20 at  7:05 AM
 */
public class StoreFacade implements Serializable {
    public MyLoggingFacade getLogger() {
        return logger;
    }

    public void setLogger(MyLoggingFacade logger) {
        this.logger = logger;
    }

    transient MyLoggingFacade logger = null;
    transient ConfigurationNode configurationNode;
    transient OA2SE environment = null;


    public ConfigurationLoader<? extends AbstractEnvironment> getLoader() {
        return new OA2ConfigurationLoader<OA2SE>(getConfigurationNode(), getLogger());
    }

    public ConfigurationNode getConfigurationNode() {
        return configurationNode;
    }

    public void setConfigurationNode(ConfigurationNode configurationNode) {
        this.configurationNode = configurationNode;
    }


    public OA2SE getEnvironment() throws Exception {
        if (environment == null) {
            environment = (OA2SE) getLoader().load();
        }
        return environment;
    }

    boolean initCalled = false;

    protected void checkInit() {
        if (!initCalled) {
            throw new IllegalStateException("Error: You must call init before calling this function");
        }
    }

    protected void init(String configFile, String cfgName) {
        try {
            setConfigurationNode(ConfigUtil.findConfiguration(configFile, cfgName, "service"));
        } catch (Exception x) {
            if (x instanceof RuntimeException) {
                throw (RuntimeException) x;
            }
            throw new GeneralException("Error initializing client management:" + x.getMessage(), x);
        }
        initCalled = true;
    }


    protected String INIT_NAME = "init";

    public static final String STORE_TYPE_CLIENT = "client";
    public static final String STORE_TYPE_APPROVALS = "client_approval";
    public static final String STORE_TYPE_TRANSACTION = "transaction";
    public static final String STORE_TYPE_TX_STORE = "tx_record";
    public static final String STORE_TYPE_PERMISSION_STORE = "permission";
    public static final String STORE_TYPE_ADMIN_CLIENT_STORE = "admin_client";

    protected String checkInitMessage = "Be sure you have called the " + INIT_NAME + " function first or this will fail.";

    String file = null;
    String cfgName = null;
    String storeType = null;
    String FILE_ARG = "file";
    String NAME_ARG = "name";
    String TYPE_ARG = "type";

    public class InitMethod implements QDLFunction {
        @Override
        public String getName() {
            return INIT_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0, 1, 3};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {

            if (objects.length == 1) {
                if (!(objects[0] instanceof StemVariable)) {
                    throw new IllegalArgumentException("Error: A single argument must be a stem.");
                }
                StemVariable stem = (StemVariable) objects[0];
                file = stem.getString(FILE_ARG);
                cfgName = stem.getString(NAME_ARG);
                storeType = stem.getString(TYPE_ARG);
            }

            if (objects.length == 3) {
                for (int j = 0; j < objects.length; j++) {
                    if (!(objects[j] instanceof String)) {
                        throw new IllegalArgumentException("Error: argument " + j + " must be a string.");
                    }
                }
                file = (String) objects[0];
                cfgName = (String) objects[1];
                storeType = (String) objects[2];
            }
            // Implicit case of zero args is here too.
            if (isTrivial(file) || isTrivial(cfgName) || isTrivial(storeType)) {
                throw new IllegalArgumentException("Error: Missing argument");
            }

            doSetup();
            return true;
        }

        /*
        module_import('oa2:/qdl/store', 'c')
        c#init('/home/ncsa/dev/csd/config/server-oa2.xml', 'localhost:oa4mp.oa2.mariadb', 'client')

        cli. :=  c#read('localhost:command.line')

        module_import('oa2:/qdl/store', 't')
        t#init('/home/ncsa/dev/csd/config/server-oa2.xml', 'localhost:oa4mp.oa2.mariadb', 'transaction')

         t. := t#search('access_token', '.*165.*');
         t.0

         t23. := t#search('access_token', '.*23.*');
             */
        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            switch (argCount) {
                case 0:
                    doxx.add(getName() + "() - Reinitialize this, usually after saving then loading it, since connections to stores must be recreated. ");

                    break;
                case 1:
                    doxx.add(getName() + "(stem.) - reads the configuration file and then loads the configuration with the given name and store type. ");
                    doxx.add("the stem entries have keys file, name and store_type.");
                    doxx.add("The store_type tells which type of store is to be used.");
                    doxx.add("Store types are " + STORE_TYPE_CLIENT + ", " + STORE_TYPE_APPROVALS + ", " + STORE_TYPE_TRANSACTION + ", " + STORE_TYPE_TX_STORE);

                    break;
                case 3:
                    doxx.add(getName() + "(file, name, store_type) - reads the configuration file and then loads the configuration with the given name and store type. ");
                    break;
                default:
                    return doxx;
            }

            doxx.add("For a first initialization, you may either supply each argument directly or simply pass in a stem with the entries of file, name and store_type.");
            doxx.add("This must be called before any other function.");
            return doxx;
        }
    }

    protected void doSetup() {
        if(isTrivial(file) || isTrivial(cfgName) || isTrivial(storeType)){
            // case is that init is not called. This should be benign at this point.
            return;
        }
        init(file, cfgName);
        try {
            setStoreAccessor(createAccessor(storeType));
        } catch (Exception x) {
            // If loading the store blows up,
            throw new QDLException("Error loading store: for file " + file + ", config " + cfgName + ", type " + storeType);
        }
        if (storeAccessor == null) {
            // If there is no such store.
            throw new QDLException("Error loading store: for file " + file + ", config " + cfgName + ", type " + storeType);
        }
    }

    /**
     * Thanks to the vagaraies of Java non-static inner class inheritence, it is just best if this
     * livesin the encloising class and is called. That means it can be easily (and predictably) overridden.
     *
     * @param storeType
     * @return
     * @throws Exception
     */
    protected QDLStoreAccessor createAccessor(String storeType) throws Exception {
        QDLStoreAccessor storeAccessor = null;
        switch (storeType) {

            case STORE_TYPE_ADMIN_CLIENT_STORE:
                storeAccessor = new QDLStoreAccessor(storeType, getEnvironment().getAdminClientStore(), getEnvironment().getMyLogger());
                storeAccessor.setMapConverter(new AdminClientStemMC(getEnvironment().getAdminClientStore().getMapConverter()));
                break;
            case STORE_TYPE_CLIENT:
                storeAccessor = new QDLStoreAccessor(storeType, getEnvironment().getClientStore(), getEnvironment().getMyLogger());
                storeAccessor.setMapConverter(new ClientStemMC(getEnvironment().getClientStore().getMapConverter()));
                break;
            case STORE_TYPE_APPROVALS:
                storeAccessor = new QDLStoreAccessor(storeType, getEnvironment().getClientApprovalStore(), getEnvironment().getMyLogger());
                MapConverter mc = getEnvironment().getClientApprovalStore().getMapConverter();

                storeAccessor.setMapConverter(new ApprovalStemMC(mc));
                break;
            case STORE_TYPE_TRANSACTION:
                storeAccessor = new QDLStoreAccessor(storeType, (Store) getEnvironment().getTransactionStore(), getEnvironment().getMyLogger());
                storeAccessor.setMapConverter(new TransactionStemMC((getEnvironment().getTransactionStore()).getMapConverter(), getEnvironment().getClientStore()));
                break;
            case STORE_TYPE_TX_STORE:
                storeAccessor = new QDLStoreAccessor(storeType, getEnvironment().getTxStore(), getEnvironment().getMyLogger());
                storeAccessor.setMapConverter(new TXRStemMC(getEnvironment().getTxStore().getMapConverter()));
                break;

        }
        return storeAccessor;
    }

    public String TO_XML_NAME = "toXML";

    public class ToXML implements QDLFunction {
        @Override
        public String getName() {
            return TO_XML_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            if (objects.length != 1) {
                throw new IllegalArgumentException("Error: " + getName() + " requires a single argument.");
            }
            if (!(objects[0] instanceof StemVariable)) {
                throw new IllegalArgumentException("Error: " + getName() + " requires a stem argument.");
            }
            StemVariable stem = (StemVariable) objects[0];
            // last hurdle, make sure it's not just a list of stems
            if (stem.isList()) {
                throw new IllegalArgumentException("Error: " + getName() + " does not accept lists.");
            }
            return getStoreAccessor().toXML((StemVariable) objects[0]);
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(stem.) - converts the objec to its XML (serialization) format.");
            doxx.add("Serialization format is a good way to store, backup or send configurations.");
            doxx.add("See also: " + FROM_XML_NAME);
            return doxx;
        }
    }

    public class FromXML implements QDLFunction {
        @Override
        public String getName() {
            return FROM_XML_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            if (objects.length != 1) {
                throw new IllegalArgumentException("Error: " + getName() + " requires a single argument.");
            }
            if (!(objects[0] instanceof String)) {
                throw new IllegalArgumentException("Error: " + getName() + " requires a string argument.");
            }


            return getStoreAccessor().fromXML((String) objects[0]);
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(xml_doc) - converts a serialized object into a stem.");
            doxx.add("See also: " + TO_XML_NAME);
            return doxx;
        }
    }

    public String FROM_XML_NAME = "fromXML";

    public QDLStoreAccessor getStoreAccessor() {
        return storeAccessor;
    }

    public void setStoreAccessor(QDLStoreAccessor storeAccessor) {
        this.storeAccessor = storeAccessor;
    }

    protected transient QDLStoreAccessor storeAccessor;
    protected String CREATE_NAME = "create";

    public class Create implements QDLFunction {
        @Override
        public String getName() {
            return CREATE_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0, 1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            if (objects.length == 1) {
                if (objects[0] instanceof String) {
                    return getStoreAccessor().create((String) objects[0]);
                }
                throw new IllegalArgumentException("Error: The argument must be a string identifier.");
            }
            return getStoreAccessor().create(null);
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            if (argCount == 0) {
                doxx.add(getName() + "() - Create a new blank object of this type.");
            }
            if (argCount == 1) {
                doxx.add(getName() + "(id) - Create a new blank object of this type with the given identifier.");
            }
            doxx.add("You must save this object for it to be in the store.");
            return doxx;
        }
    }

    protected String READ_NAME = "read";

    public class ReadObject implements QDLFunction {
        @Override
        public String getName() {
            return READ_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            checkInit();
            try {
                return getStoreAccessor().get(BasicIdentifier.newID(objects[0].toString()));
            } catch (Throwable t) {
                throw new QDLException("Error: Could not find the object with id \"" + objects[0].toString() + "\"");
            }
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(id) - read the stored object with the given identifier. This will return a stem representation. ");
            doxx.add("You may have several active objects at once.");
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    protected String UPDATE_NAME = "update";

    public class UpdateObject implements QDLFunction {
        @Override
        public String getName() {
            return UPDATE_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            checkInit();
            if (!(objects[0] instanceof StemVariable)) {
                throw new IllegalArgumentException("Error: The argument must be a stem variable");
            }
            StemVariable stemVariable = (StemVariable) objects[0];
            List<Boolean> out = getStoreAccessor().saveOrUpdate(stemVariable, false);
            if (out.size() == 0) {
                return Boolean.FALSE;
            }
            if (out.size() == 1) {
                return out.get(0);
            }
            StemVariable stemVariable1 = new StemVariable();
            stemVariable1.addList(out);
            return stemVariable1;
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + " (stem.) updates and existing object in the store. If the object exists, this will fail.");
            doxx.add("See also: " + SAVE_NAME);
            return doxx;
        }
    }

    protected String SAVE_NAME = "save";

    public class SaveObject implements QDLFunction {
        @Override
        public String getName() {
            return SAVE_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        // cm#init('${cfg_file}', '${cfg_name}')
        //  client. := cm#read('${id}')
        // cm#save(client.)
        @Override
        public Object evaluate(Object[] objects, State state) {
            checkInit();
            if (!(objects[0] instanceof StemVariable)) {
                throw new IllegalArgumentException("Error: The argument must be a stem variable");
            }
            StemVariable stemVariable = (StemVariable) objects[0];
            List<Boolean> out = getStoreAccessor().saveOrUpdate(stemVariable, true);
            if (out.size() == 0) {
                return Boolean.FALSE;
            }
            if (out.size() == 1) {
                return out.get(0);
            }
            StemVariable stemVariable1 = new StemVariable();
            stemVariable1.addList(out);
            return stemVariable1;
        }


        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(obj.) - save the object to the store. This returns true if the operation succeeds.");
            doxx.add(getName() + "This may also be a list of stems and each will be saved if possible. Be sure you send along what you want!");
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    protected String SEARCH_NAME = "search";

    public class Search implements QDLFunction {
        @Override
        public String getName() {
            return SEARCH_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{2};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            checkInit();
            String key = objects[0].toString();
            String regex = objects[1].toString();
            return getStoreAccessor().search(key, regex, true);
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(key, regex) -  search for all clients with the given key whose values satisfy the regex.");
            doxx.add("Note especially #1: This returns a bunch of stems, one for each object that is found, so it is equivalent to a multi-read");
            doxx.add("Note especially #2: This may be a huge result if the regex is too general. Do eb careful.");
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    protected String SIZE_NAME = "size";

    public class Size implements QDLFunction {
        @Override
        public String getName() {
            return SIZE_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0, 1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            checkInit();
            boolean includeVersions = false;
            if (objects.length == 1) {
                if (objects[0] instanceof Boolean) {
                    includeVersions = (Boolean) objects[0];
                } else {
                    throw new IllegalArgumentException("The first argument of " + SIZE_NAME + ", if present, must be a boolean.");
                }
            }
            try {
                return getStoreAccessor().size(includeVersions);
            } catch (Exception e) {
                throw new QDLException("Error: COuld not determine the size of the store:" + e.getMessage(), e);
            }
        }


        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "([includeVersions) - returns a count of how many clients there are in this store.");
            doxx.add(getName() + "includeVersions will count the versions in the store too if true, and ignore them if false.");
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    protected String KEYS_NAME = "keys";

    public class Keys implements QDLFunction {
        @Override
        public String getName() {
            return KEYS_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0, 1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            //checkInit();

            if(objects.length == 1){
                if((objects[0] instanceof Boolean)){
                    if((Boolean)objects[0]) {
                        return getStoreAccessor().getStoreKeys().identifier();
                    }
                }
            }
            return getStoreAccessor().listKeys();
        }


        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "() - list the keys (names of properties) for the objects in the store.");
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    protected String REMOVE_NAME = "remove";

    public class Remove implements QDLFunction {
        @Override
        public String getName() {
            return REMOVE_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            checkInit();
            if (objects.length != 1) {
                throw new IllegalArgumentException("Error: You must specify an identifier for " + REMOVE_NAME);
            }
            String id = null;
            if (objects[0] instanceof String) {
                id = (String) objects[0];
            }
            if (objects[0] instanceof StemVariable) {
                StemVariable stemVariable = (StemVariable) objects[0];
                if (stemVariable.containsKey(getStoreAccessor().getStoreKeys().identifier())) {
                    id = (String) stemVariable.get(getStoreAccessor().getStoreKeys().identifier());
                } else {
                    throw new IllegalArgumentException("Error: The stem does not contain the key \"" + getStoreAccessor().getStoreKeys().identifier() + "\", hence there is no unique identifier given.");
                }
            }
            if (isTrivial(id)) {
                throw new IllegalArgumentException("Error: argument must be a string for " + REMOVE_NAME);
            }

            try {
                return getStoreAccessor().remove(BasicIdentifier.newID(id));
            } catch (Throwable e) {
                throw new QDLException("Error: Could not remove object with id " + objects[0] + ":" + e.getMessage());
            }
        }


        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(id) - remove the client with the given identifier. Returns true if this worked.");
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    public String STORE_TYPES_STEM_NAME = "store_types.";

    public class StoreTypes implements QDLVariable {
        StemVariable storeTypes = null;

        @Override
        public String getName() {
            return STORE_TYPES_STEM_NAME;
        }

        @Override
        public Object getValue() {
            if (storeTypes == null) {
                storeTypes = new StemVariable();
                storeTypes.listAppend(STORE_TYPE_CLIENT);
                storeTypes.listAppend(STORE_TYPE_APPROVALS);
                storeTypes.listAppend(STORE_TYPE_ADMIN_CLIENT_STORE);
                storeTypes.listAppend(STORE_TYPE_PERMISSION_STORE);
                storeTypes.listAppend(STORE_TYPE_TRANSACTION);
                storeTypes.listAppend(STORE_TYPE_TX_STORE);
            }
            return storeTypes;
        }
    }

    public String STORE_HELP_NAME = "store_help";

    public class FacadeHelp implements QDLVariable {
        @Override
        public String getName() {
            return STORE_HELP_NAME;
        }


        String help = null;


        @Override
        public Object getValue() {
            if (help == null) {
                StringBuffer s = new StringBuffer();
                s.append("The store module(s) allow you to access OA4MP stores in QDL. Supported stores are\n");
                s.append(STORE_TYPE_CLIENT + " for clients.\n");
                s.append(STORE_TYPE_APPROVALS + "  for approvals of clients (including admin clients)\n");
                s.append(STORE_TYPE_PERMISSION_STORE + " for managing the permissions between admins and their clients. Use the p_store module\n");
                s.append(STORE_TYPE_ADMIN_CLIENT_STORE + " for administrative clients\n");
                s.append(STORE_TYPE_TX_STORE + " for tokens created by the exchange endpoint (RFC 8693)\n");
                s.append(STORE_TYPE_TRANSACTION + " for pending transactions.\n");
                s.append("There is a list of these in the variable " + STORE_TYPES_STEM_NAME + " \n");
                s.append("\n" + "Every store allows for the following commands (online help is available for these in the workspace\n");
                s.append("using e.g.\n");
                s.append("\n)help p_store#init\n");
                s.append("\n" + FROM_XML_NAME + " Take and object's XML serialization (as a string, e.g. in a file) and convert to a stem.\n");
                s.append(INIT_NAME + " initialize the store. You cannot use a store until you call this.\n");
                s.append(KEYS_NAME + " Lists the keys possible in the stem for this store.\n");
                s.append(READ_NAME + " Read an object from the store by identifier. Note the result is stem\n");
                s.append(REMOVE_NAME + " Remove an object from the store by identifier.\n");
                s.append(SAVE_NAME + " Save an object to the store. If the object exists, it is updated, otherwise a new object is created in the store.\n");
                s.append(SEARCH_NAME + " Search the store by key and value for all objects. This returns a list of stems (which may be huge -- plan your queries!)\n");
                s.append(SIZE_NAME + " The size of the store, i.e., number of objects in the store\n");
                s.append(TO_XML_NAME + " Serialize a stem object into XML (as a string).\n");
                s.append(UPDATE_NAME + " Updates an existing object. This will fail if the object does not exist.\n");
                s.append("*" + PermissionStoreFacade.ADMINS_NAME + " Lists the admins for a given client\n");
                s.append("*" + PermissionStoreFacade.CLIENTS_NAME + " Lists the clients for a given admin\n");
                s.append("*" + PermissionStoreFacade.CLIENT_COUNT_NAME + " Return the number of clients this associated with the admin.\n");
                s.append("* = only available in permission stores.\n");
                s.append("\nNote that you should create a module for each type of store you want and each store using the " + ControlEvaluator.MODULE_IMPORT + " command\n");
                s.append("The alias should be descriptive, so something like 'client' or 'trans' and yes, you may have as many\n");
                s.append("imports as you like talking to different stores -- this is an easy way to move objects from one store to another\n");
                s.append("\n");
                s.append("\n");
                help = s.toString();
            }
            return help;
        }
    }
}
