package org.oa4mp.server.qdl.storage;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.util.configuration.XMLConfigUtil;
import org.apache.commons.configuration.tree.ConfigurationNode;
import org.oa4mp.delegation.common.storage.TransactionStore;
import org.oa4mp.delegation.server.storage.ClientStore;
import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.loader.OA2ConfigurationLoader;
import org.qdl_lang.exceptions.BadArgException;
import org.qdl_lang.extensions.QDLFunction;
import org.qdl_lang.extensions.QDLVariable;
import org.qdl_lang.state.State;
import org.qdl_lang.variables.QDLList;
import org.qdl_lang.variables.QDLNull;
import org.qdl_lang.variables.QDLStem;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import static edu.uiuc.ncsa.security.core.util.StringUtils.isTrivial;

/**
 * The class with the inner classes that do all the work here.
 * <p>Created by Jeff Gaynor<br>
 * on 12/18/20 at  7:05 AM
 */
public class StoreFacade /*implements QDLMetaModule*/ {
    QDLStem types;

    public QDLStem getStoreTypes() {
        if (types == null) {
            types = new QDLStem();
            types.put("client", STORE_TYPE_CLIENT);
            types.put("approval", STORE_TYPE_APPROVALS);
            types.put("admin", STORE_TYPE_ADMIN_CLIENT_STORE);
            types.put("permission", STORE_TYPE_PERMISSION_STORE);
            types.put("transaction", STORE_TYPE_TRANSACTION);
            types.put("tx", STORE_TYPE_TX_STORE);
        }
        return types;
    }

    public MyLoggingFacade getLogger() {
        return logger;
    }

    public void setLogger(MyLoggingFacade logger) {
        this.logger = logger;
    }

    transient MyLoggingFacade logger = null;
    transient ConfigurationNode configurationNode;
    transient protected OA2SE environment = null;


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
            // pipe all startup messages to dev null, essentially.
            PrintStream out = System.out;
            PrintStream err = System.err;
            System.setOut(new PrintStream(OutputStream.nullOutputStream()));
            System.setErr(new PrintStream(OutputStream.nullOutputStream()));
            environment = (OA2SE) getLoader().load();
            System.setOut(out);
            System.setErr(err);
        }
        return environment;
    }

    boolean initCalled = false;

    protected void checkInit() {
        if (!initCalled) {
            throw new IllegalStateException(" You must call init before calling this function");
        }
    }

    protected void init(String configFile, String cfgName) throws Throwable {
        setConfigurationNode(XMLConfigUtil.findConfiguration(configFile, cfgName, "service"));
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
    String VERBOSE_ON_ARG = "verbose_on";

    public class InitMethod implements QDLFunction {
        @Override
        public String getName() {
            return INIT_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0, 1, 2, 3};
        }

        @Override
        public Object evaluate(Object[] objects, State state) throws Throwable {
            boolean verboseOn = false;
            switch (objects.length) {
                case 0:
                    // used for re-initializing this, e.g. post serialization.
                    break;
                case 1:
                    if (!(objects[0] instanceof QDLStem)) {
                        throw new BadArgException("monadic " + getName() + " requires  a stem.",0);
                    }
                    QDLStem stem = (QDLStem) objects[0];
                    file = stem.getString(FILE_ARG);
                    cfgName = stem.getString(NAME_ARG);
                    storeType = stem.getString(TYPE_ARG);
                    if (stem.containsKey(VERBOSE_ON_ARG)) {
                        verboseOn = stem.getBoolean(VERBOSE_ON_ARG);
                    }
                    break;
                case 2:
                    if (!(objects[0] instanceof QDLStem)) {
                        throw new BadArgException("dyadic " + getName() + " requires a stem as its first argument",0);
                    }
                    QDLStem stem2 = (QDLStem) objects[0];
                    if (!(objects[1] instanceof String)) {
                        throw new BadArgException("dyadic " + getName() + " requires a string, the store type, as its second argument",1);
                    }
                    file = stem2.getString(FILE_ARG);
                    cfgName = stem2.getString(NAME_ARG);
                    storeType = (String) objects[1];
                    if (stem2.containsKey(VERBOSE_ON_ARG)) {
                        verboseOn = stem2.getBoolean(VERBOSE_ON_ARG);
                    }
                    break;
                case 3:
                    for (int j = 0; j < objects.length; j++) {
                        if (!(objects[j] instanceof String)) {
                            throw new BadArgException(" argument " + j + " must be a string.",j);
                        }
                    }
                    file = (String) objects[0];
                    cfgName = (String) objects[1];
                    storeType = (String) objects[2];
                    break;
                default:
                    throw new IllegalArgumentException("Incorrect argument count");
            }

            doSetup(verboseOn);
            return true;
        }

        /*
        Quick modules 2.0 test.
        client := import('oa2:/qdl/store')
        client#init('/home/ncsa/dev/csd/config/server-oa2.xml', 'localhost:oa4mp.oa2.mariadb', 'client')
        client#count();
        client#keys()
        client#read('localhost:command.line2')

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
                    doxx.add(getName() + "(cfg.) - reads the configuration file and then loads the configuration with the given name and store type. ");
                    doxx.add("the stem entries have keys file, name and store_type.");
                    doxx.add("The store_type tells which type of store is to be used.");
                    doxx.add("Store types are in " + STORE_TYPES_STEM_NAME);
                    break;
                case 2:
                    doxx.add(getName() + "(cfg., store_type) - uses the cfg. stem, but allows you to override the store type");
                    doxx.add("if present in the cfg.");
                    break;
                case 3:
                    doxx.add(getName() + "(file, name, store_type) - reads the configuration file and then loads the configuration with the given name and store type. ");
                    break;
                default:
                    return doxx;
            }

            doxx.add("For a first initialization, you may either supply each argument directly ");
            doxx.add("or simply pass in a stem with the entries of " + FILE_ARG + ", " + NAME_ARG + ", " + TYPE_ARG +
                    " and " + VERBOSE_ON_ARG);
            doxx.add("This must be called before any other function.");
            return doxx;
        }
    }

    protected void doSetup(boolean verboseOn) throws Throwable {
        if (isTrivial(file) || isTrivial(cfgName) || isTrivial(storeType)) {
            // case is that init is not called. This should be benign at this point.
            return;
        }
        // Since loading the system may print out a ton of random messages to the console,
        // this captures everything and suppresses it.

        PrintStream out = System.out;
        PrintStream err = System.err;
        if (!verboseOn) {
            System.setOut(new PrintStream(OutputStream.nullOutputStream()));
            System.setErr(new PrintStream(OutputStream.nullOutputStream()));
        }
        init(file, cfgName);
        if (!verboseOn) {
            System.setOut(out);
            System.setErr(err);
        }
        setStoreAccessor(createAccessor(storeType));

        if (storeAccessor == null) {
            // If there is no such store.
            throw new RuntimeException("unsupported type for store '" + storeType + "': config file =" + file + ", config name= " + cfgName);
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
                storeAccessor.setMapConverter(createTransactionStemMC(getEnvironment().getTransactionStore(), getEnvironment().getClientStore()));
                break;
            case STORE_TYPE_TX_STORE:
                storeAccessor = new QDLStoreAccessor(storeType, getEnvironment().getTxStore(), getEnvironment().getMyLogger());
                storeAccessor.setMapConverter(new TXRStemMC(getEnvironment().getTxStore().getMapConverter(),
                        getEnvironment().getTxStore(),
                        getEnvironment().getClientStore()));
                break;
            default:
                throw new IllegalArgumentException("unsupported store '" + storeType + "'");

        }
        return storeAccessor;
    }

    protected TransactionStemMC createTransactionStemMC(TransactionStore transactionStore, ClientStore clientStore) {
        return new TransactionStemMC(transactionStore.getMapConverter(), clientStore);
    }

    public String TO_XML_NAME = "to_xml";

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
            if (!(objects[0] instanceof QDLStem)) {
                throw new BadArgException(getName() + " requires a stem argument.",0);
            }
            QDLStem stem = (QDLStem) objects[0];
            if (stem.isEmpty()) {
                return "";
            }
            // last hurdle, make sure it's not just a list of stems
            if (!stem.isList()) {
                return getStoreAccessor().toXML((QDLStem) objects[0]);
            }
            QDLStem out = new QDLStem();
            for (Object key : stem.keySet()) {
                try {
                    // Skip items that fail, replacing them with nulls
                    out.putLongOrString(key, getStoreAccessor().toXML((QDLStem) stem.get(key)));
                } catch (Throwable t) {
                    getLogger().warn("Could not convert object to XML:" + t.getMessage(), t);
                    out.putLongOrString(key, QDLNull.getInstance());
                }
            }
            return out;
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(stem. | [stem0., stem1.,...]) - converts the object(s)  XML (serialization) format.");
            doxx.add("Serialization format is a good way to store, backup or send configurations.");
            doxx.add("If you supply a single stem for an object, that is processed, or you may supply a list of");
            doxx.add("object. The result is either a string (of XML) or a null if the conversion failed.");
            doxx.add("E.g.");
            doxx.add("   x. := clients#to_xml(clients#search('client_id','.*ligo.*))");
            doxx.add("would search for all client ids that contain 'ligo' and serialize them the XML");
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
            if ((objects[0] instanceof String)) {
                return getStoreAccessor().fromXML((String) objects[0]);
            }
            if (!(objects[0] instanceof QDLStem)) {
                throw new BadArgException(getName() + " requires a string argument or stem of them,.",0);
            }
            QDLStem arg = (QDLStem) objects[0];
            QDLStem out = new QDLStem();
            for (Object key : arg.keySet()) {
                Object obj = arg.get(key);
                if (obj instanceof String) {
                    out.putLongOrString(key, getStoreAccessor().fromXML((String) obj));
                } else {
                    out.putLongOrString(key, QDLNull.getInstance());
                }

            }
            return out;
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(xml_doc) - converts a serialized object into a stem.");
            doxx.add("See also: " + TO_XML_NAME);
            return doxx;
        }
    }

    public String FROM_XML_NAME = "from_xml";

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
                throw new BadArgException(" The argument must be a string identifier.",0);
            }
            return getStoreAccessor().create(null);
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            if (argCount == 0) {
                doxx.add(getName() + "() - Create a new object of this type using system defaults.");
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
            return new int[]{1, 2};
        }

        @Override
        public Object evaluate(Object[] objects, State state) throws Throwable {
            checkInit();
            boolean isScalar = false;
            if (objects.length == 2) {
                // then it is of the form (id, int)
                if (!(objects[0] instanceof String)) {
                    throw new BadArgException("dyadic " + getName() + " requires a string as its first argument",0);
                }
                if (!(objects[1] instanceof Long)) {
                    throw new BadArgException("dyadic " + getName() + " requires an integer as its seconds argument",1);

                }
                QDLStem QDLStem = getStoreAccessor().getVersion(BasicIdentifier.newID((String) objects[0]), (Long) objects[1]);
                if (QDLStem.isEmpty()) {
                    return QDLNull.getInstance();
                }
                return QDLStem;
            }
            // only length 1 allowed at this point
            // most basic case. Just asking for an id.
            if (objects[0] instanceof String) {
                return getSingleEntry(objects[0]);
            }
            if (!(objects[0] instanceof QDLStem)) {
                throw new BadArgException("monadic " + getName() + " requires a stem as its first argument",0);
            }
            QDLStem argStem = (QDLStem) objects[0];
            if (argStem.isList()) {
                // then it is assumed to be [id, int] and a version
                if (isValueStem(argStem)) {
                    // this is a simple versioned id.
                    QDLList ql = argStem.getQDLList();
                    QDLStem QDLStem = getStoreAccessor().getVersion(BasicIdentifier.newID((String) ql.get(0L)), (Long) ql.get(1L));
                    if (QDLStem.isEmpty()) {
                        return QDLNull.getInstance();
                    }
                    return QDLStem;
                }
            }


            // Finally, we have a generic stem of id or [id,version]
            QDLStem outStem = new QDLStem();
            for (Object key : argStem.keySet()) {
                Object value = argStem.get(key);
                Object result = QDLNull.getInstance();
                if (value instanceof String) {
                    result = getSingleEntry(value);
                }
                if (isValueStem(value)) {
                    QDLList ql = ((QDLStem) value).getQDLList();
                    result = getVersionedSingleEntry(ql.get(0L), ql.get(1L));
                }
                outStem.putLongOrString(key, result);
            }

            return outStem;
        }


        /**
         * Gets a single object or return QDLNull if no such object.
         *
         * @param object
         * @return
         */
        private Object getSingleEntry(Object object) {
            QDLStem QDLStem = getStoreAccessor().get(BasicIdentifier.newID((String) object));
            if (QDLStem.isEmpty()) {
                return QDLNull.getInstance();
            }
            return QDLStem;
        }

        private Object getVersionedSingleEntry(Object object, Object version) throws IOException {
            QDLStem QDLStem = getStoreAccessor().getVersion(BasicIdentifier.newID((String) object), (Long) version);
            if (QDLStem.isEmpty()) {
                return QDLNull.getInstance();
            }
            return QDLStem;
        }


        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            switch (argCount) {
                case 1:
                    doxx.add(getName() + "(id | id.) = get an object or stem of them.");
                    doxx.add("id. may be a stem of simple strings (ids), version entries [id, version],");
                    doxx.add("or a mixture. The result is conformable to the argument.");
                    break;
                case 2:
                    doxx.add(getName() + "(id, version) - get a versioned object");
                    break;
            }
            doxx.add("If there is no such element for a given id, a null will be returned");
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    private boolean isValueStem(Object value) {
        if (!(value instanceof QDLStem)) {
            return false;
        }
        if (!((QDLStem) value).isList()) {
            return false;
        }
        QDLList ql = ((QDLStem) value).getQDLList();
        return ql.size() == 2 && (ql.get(0L) instanceof String) && (ql.get(1L) instanceof Long);
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
            if (!(objects[0] instanceof QDLStem)) {
                throw new BadArgException(" The argument must be a stem variable",0);
            }
            QDLStem QDLStem = (QDLStem) objects[0];
            List<Boolean> out = getStoreAccessor().saveOrUpdate(QDLStem, false);
            if (out.size() == 0) {
                return Boolean.FALSE;
            }
            if (out.size() == 1) {
                return out.get(0);
            }
            QDLStem QDLStem1 = new QDLStem();
            QDLStem1.addList(out);
            return QDLStem1;
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + " (stem.) updates and existing object in the store. If the object does not exist, this will fail.");
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
            if (!(objects[0] instanceof QDLStem)) {
                throw new BadArgException(" The argument must be a stem variable",0);
            }
            QDLStem QDLStem = (QDLStem) objects[0];
            List<Boolean> out = getStoreAccessor().saveOrUpdate(QDLStem, true);
            if (out.size() == 0) {
                return Boolean.FALSE;
            }
            if (out.size() == 1) {
                return out.get(0);
            }
            QDLStem QDLStem1 = new QDLStem();
            QDLStem1.addList(out);
            return QDLStem1;
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
            doxx.add("Note #1: This returns a bunch of stems, one for each object that is found, so it is equivalent to a multi-read");
            doxx.add("Note #2: This may be a huge result if the regex is too general. Do be careful.");
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    protected String COUNT_NAME = "count";

    public class Count implements QDLFunction {
        @Override
        public String getName() {
            return COUNT_NAME;
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
                    throw new BadArgException("The first argument of " + COUNT_NAME + ", if present, must be a boolean.",0);
                }
            }
            return getStoreAccessor().size(includeVersions);
        }


        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            switch (argCount) {
                case 0:
                    doxx.add(getName() + "() -count the number of entries in the store");
                    break;
                case 1:
                    doxx.add(getName() + "(includeVersions) will count the versions in the store too if true, ");
                    doxx.add("and ignore them if false. The default is false.");
                    break;
            }
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

            if (objects.length == 1) {
                if ((objects[0] instanceof Boolean)) {
                    if ((Boolean) objects[0]) {
                        return getStoreAccessor().getStoreKeys().identifier();
                    }
                } else {
                    throw new BadArgException(getName() + " requires a boolean as its argument if present",0);
                }
            }
            return getStoreAccessor().listKeys();
        }


        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            switch (argCount) {
                case 0:
                    doxx.add(getName() + "() - list the column names  for the objects in the store.");
                    break;
                case 1:
                    doxx.add(getName() + "(show_primary_key) - list the primary keys this store.");
                    doxx.add("show_primary_key - boolean, if true show the key, if false, show all keys");
                    break;

            }
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
            return new int[]{1, 2};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            checkInit();
            if (objects.length == 2) {
                if (!(objects[0] instanceof String)) {
                    throw new BadArgException("dyadic " + getName() + " requires a string as its first argument.",0);
                }
                if (!(objects[1] instanceof Long)) {
                    throw new BadArgException("dyadic " + getName() + " requires a long as its second argument.",1);
                }
                getStoreAccessor().getStoreArchiver().remove(BasicIdentifier.newID((String) objects[0]), (Long) objects[1]);
                return Boolean.TRUE;
            }
            String id = null;
            if (objects[0] instanceof String) {
                id = (String) objects[0];
                return getStoreAccessor().remove(BasicIdentifier.newID(id));
            }
            if (!(objects[0] instanceof QDLStem)) {
                throw new BadArgException("monadic " + getName() + " requires a string as its first argument.",0);
            }
            QDLStem arg = (QDLStem) objects[0];
            QDLStem outStem = new QDLStem();
            for (Object key : arg.keySet()) {
                Object value = arg.get(key);
                if (value instanceof String) {
                    outStem.putLongOrString(key, getStoreAccessor().remove(BasicIdentifier.newID((String) value)));
                }else{
                    VID vid = toVID(value);
                    if (vid != null) {
                        try {
                            getStoreAccessor().getStoreArchiver().remove(vid.id, vid.version);
                            outStem.putLongOrString(key, Boolean.TRUE);
                        } catch (Exception e) {
                            outStem.putLongOrString(key, Boolean.FALSE);
                        }
                    }
                }
            }
            return outStem;
        }


        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            switch (argCount){
                case 1:
                    doxx.add(getName() + "(id | ids.) - delete a single object with id, or a stem of them.");
                    doxx.add("The elements of the stem may be simple strings or [id, version] pairs.");
                    break;
                case 2:
                    doxx.add(getName()+ "(id, version) - remove the given version from the system.");
                    break;
            }
            doxx.add("This returns a conformable argument with a true if the object is no longer on the");
            doxx.add("system and a flase otherwise. If an index in the argument is missing, then the argument");
            doxx.add("could not be processed and was skipped.");
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    public static String STORE_TYPES_STEM_NAME = "$$STORE_TYPE.";

    public class StoreType implements QDLVariable {
        QDLStem storeTypes = null;

        @Override
        public String getName() {
            return STORE_TYPES_STEM_NAME;
        }

        @Override
        public Object getValue() {
            return getStoreTypes();
        }
    }
    /**
     * Convert a list of objects to version id stems. The name is the name of the calling function, so
     * error can be better created.
     *
     * @param objects
     * @param name
     * @return
     */
    protected QDLStem convertArgsToVersionIDs(Object[] objects, String name) {
        QDLStem out = null;
        if (2 < objects.length) {
            throw new IllegalArgumentException("too many arguments for " + name + ".");
        }
        if (objects.length == 2) {
            out = new QDLStem();
            QDLStem id = new QDLStem();
            if (!(objects[0] instanceof String)) {
                throw new BadArgException("dyadic " + name + " requires a string as its first argument",0);
            }
            id.put(0L, objects[0]);
            if (!(objects[1] instanceof Long)) {
                throw new BadArgException("dyadic " + name + " requires an integer as its second argument",1 );
            }
            id.put(1L, objects[1]);
            out.put(0L, id);
            return out;
        }
        // So a single argument
        if (!(objects[0] instanceof QDLStem)) {
            throw new BadArgException("monadic " + name + " requires stem as its argument",0);
        }

        QDLStem temp = (QDLStem) objects[0];
        if (temp.isList() && temp.size() == 2) {
            if ((temp.get(0L) instanceof String) && (temp.get(1L) instanceof Long)) {
                out = new QDLStem();
                out.put(0L, temp);
            }
        }
        return (QDLStem) objects[0]; // It was the right format
    }

    protected String VERSION_CREATE_NAME = "version";

    /**
     * Create the archived version of an object. There are several cases.
     */
    public class CreateVersion implements QDLFunction {
        @Override
        public String getName() {
            return VERSION_CREATE_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            checkInit();
            QDLStem arg;
            boolean isScalar = false;
            switch (objects.length) {
                case 1:
                    if (objects[0] instanceof QDLStem) {
                        arg = (QDLStem) objects[0];
                    } else {
                        if (objects[0] instanceof String) {
                            isScalar = true;
                            arg = new QDLStem();
                            arg.put(0L, objects[0]);
                        } else {
                            throw new BadArgException(getName() + " requires stem or string argument",0);
                        }
                    }
                    break;
                case 0:
                    throw new IllegalArgumentException(getName() + " requires an argument");
                default:
                    throw new IllegalArgumentException(getName() + " requires at most a single argument");
            }
            QDLStem out = getStoreAccessor().archive(arg);
            if(isScalar){
                out.getQDLList().get(0L); // make conformable.
            }
            return out;

        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(id | ids.) - create versions the current stored client(s) whose ids are given.");
            doxx.add("Either supply an id for the object or a list of ids.");
            doxx.add(checkInitMessage);
            return doxx;
        }
    }


    /**
     * For a stem variable, checks that it is of the form
     * <pre>
     *     [id, version] (in QDL)
     * </pre>
     * and returns an versioned id, {@link VID}.
     * <p>
     * If the argument is not in the right format, a null is returned instead.<br/><br/>
     * This may throw other exceptions if, e.g., the id is not a valid identifier
     *
     * @param QDLStem
     * @return
     */
    protected VID toVID(QDLStem QDLStem) {
        if (QDLStem.size() != 2 || !QDLStem.isList()) {
            return null;
        }
        Object rawID = QDLStem.get(0L);
        if (!(rawID instanceof String)) {
            return null;
        }
        Identifier id = BasicIdentifier.newID(rawID.toString());
        Object v = QDLStem.get(1L);
        if (!(v instanceof Long)) {
            return null;
        }

        return new VID(id, (Long) v);
    }

    /**
     * Marker class used internally for a version id.
     */
    public class VID {
        Identifier id;
        Long version;

        public VID(Identifier id, Long version) {
            this.id = id;
            this.version = version;
        }
    }

    protected VID toVID(Object obj) {
        if (!(obj instanceof QDLStem)) {
            return null;
        }
        return toVID((QDLStem) obj);
    }

    protected String VERSION_GET_VERSIONS_NAME = "list_versions";

    public class VGetVersions implements QDLFunction {
        @Override
        public String getName() {
            return VERSION_GET_VERSIONS_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            checkInit();
            QDLStem args = null;
            boolean hasStringArg = false;
            if (objects[0] instanceof String) {
                args = new QDLStem();
                args.put(0L, objects[0]);
                hasStringArg = true;
            }
            if (objects[0] instanceof QDLStem) {
                args = (QDLStem) objects[0];
            }
            if (args == null) {
                throw new BadArgException(getName() + " requires either an id or stem of them as its argument.",0);
            }
            QDLStem out = new QDLStem();
            for (Object key : args.keySet()) {
                Identifier id = toIdentifier(args.get(key));
                if (id == null) {
                    out.putLongOrString(key, QDLNull.getInstance()); // no valid id means a null
                    continue;
                }
                QDLStem entry = new QDLStem();
                entry.addList(getStoreAccessor().getStoreArchiver().getVersionNumbers(id));
                out.putLongOrString(key, entry);
            }
            if (hasStringArg) {
                return out.get(0L); // preserve shape.
            }
            return out;
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(id | ids.) - get the versions associated with the id or stem of them.");
            doxx.add("This returns a list for each version numbers available for each identifier.");
            doxx.add("If you submit a stem of them, then each returned valus is a stem. If you submit");
            doxx.add("A single ID, then the result is a simple list.");
            doxx.add("E.g.");
            doxx.add("   " + getName() + "('uri:/my/object');");
            doxx.add("[0,1,3,7]");
            doxx.add("This is the list of valid version numbers for that object");
            doxx.add("   " + getName() + "({'client0':'uri:/my/object0', 'client42':'uri:/my/object42'});");
            doxx.add("{'client0':[1,3],'client42':[0,1,2,3,5]}");
            doxx.add("These are the valid version of each of these.");
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    protected Identifier toIdentifier(Object obj) {
        if (!(obj instanceof String)) {
            return null;
        }
        return BasicIdentifier.newID(URI.create(obj.toString()));
    }

    protected String VERSION_RESTORE_NAME = "restore";

    public class VRestore implements QDLFunction {
        @Override
        public String getName() {
            return VERSION_RESTORE_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1, 2};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            QDLStem args = convertArgsToVersionIDs(objects, getName());
            QDLStem out = new QDLStem();
            for (Object key : args.keySet()) {
                VID vid = toVID(args.get(key));
                if (vid == null) {
                    out.putLongOrString(key, Boolean.FALSE);
                    continue;
                }
                out.putLongOrString(key, getStoreAccessor().getStoreArchiver().restore(vid.id, vid.version));
            }
            return out;
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            switch (argCount) {
                case 1:
                    doxx.add(getName() + "(id. | ids.) - restore the versions for the id. or list of them");
                    break;
                case 2:
                    doxx.add(getName() + "(id, version) - restore the version numbered for the identifier");
                    break;
            }
            doxx.add("Restores the given version to be to active one.");
            doxx.add("NOTE: This overwrites the currently active object and replaces it!");
            doxx.add("Good practice is to version first whatever you are going to restore.");
            doxx.add("");
            doxx.add("");
            return doxx;
        }
    }

    protected String DIFFERENCE_NAME = "diff";


/*    @Override
    public JSONObject serializeToJSON() {
        return null;
    }

    @Override
    public void deserializeFromJSON(JSONObject jsonObject) {

    }*/
}

