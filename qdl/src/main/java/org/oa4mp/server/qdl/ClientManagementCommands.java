package org.oa4mp.server.qdl;

import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.loader.OA2ConfigurationLoader;
import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.loader.oauth2.storage.clients.OA2ClientConverter;
import org.oa4mp.delegation.server.storage.ClientApproval;
import org.qdl_lang.exceptions.BadArgException;
import org.qdl_lang.extensions.QDLFunction;
import org.qdl_lang.extensions.QDLMetaModule;
import org.qdl_lang.state.State;
import org.qdl_lang.variables.QDLStem;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.configuration.XMLConfigUtil;
import net.sf.json.JSON;
import net.sf.json.JSONObject;
import org.apache.commons.configuration.tree.ConfigurationNode;

import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/31/20 at  11:07 AM
 */
public class ClientManagementCommands implements QDLMetaModule {
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
            throw new IllegalStateException(" You must call init before calling this function");
        }
    }

    protected void init(String configFile, String cfgName) throws Throwable {

            setConfigurationNode(XMLConfigUtil.findConfiguration(configFile, cfgName, "service"));
        initCalled = true;
    }


    //  cm#init('/home/ncsa/dev/csd/config/servers.xml', 'localhost:oa4mp.oa2.mariadb')
    //    cm#read('ashigaru:command.line2');
    protected String INIT_NAME = "init";

    protected String checkInitMessage = "Be sure you have called the " + INIT_NAME + " function first or this will fail.";

    public class InitMethod implements QDLFunction {
        @Override
        public String getName() {
            return INIT_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{2};
        }

        @Override
        public Object evaluate(Object[] objects, State state) throws Throwable {
            init(objects[0].toString(), objects[1].toString());
            return true;
        }


        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(file, name) - reads the configuration file and then loads the configuration with the given name. ");
            doxx.add("This sets the configuration and name. " + READ_NAME + " is used to read a specific client by id and returns a client.");
            doxx.add("This must be called before any other function.");
            return doxx;
        }
    }

    protected String READ_NAME = "read";

    public class ReadClient implements QDLFunction {
        @Override
        public String getName() {
            return READ_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) throws Throwable {
            checkInit();
//            try {
                OA2Client client = (OA2Client) getEnvironment().getClientStore().get(BasicIdentifier.newID(objects[0].toString()));
                return toStem(client);
/*
            } catch (Throwable t) {
                throw new QDLException("Error: Could not find the client with id \"" + objects[0].toString() + "\"");
            }
*/
        }


        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(id) - read the client with the given identifier. This will return a stem representation of the client. ");
            doxx.add("You may have several active clients at once.");
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    protected QDLStem toStem(OA2Client client) throws Exception {
        if (client == null) {
            return new QDLStem();
        }
        OA2ClientConverter converter = (OA2ClientConverter) getEnvironment().getClientStore().getMapConverter();
        JSONObject jsonObject = new JSONObject();
        converter.toJSON(client, jsonObject);
        QDLStem output = new QDLStem();
        if (jsonObject.isEmpty()) {
            return output;
        }
        // The serialization form is {"client":...}. We want this to look more natural
        // It is used by RFC 7591, so we have to twiddle that
        JSONObject j2 = jsonObject.getJSONObject("client");

        output.fromJSON(j2);
        return output;
    }

    protected String SAVE_NAME = "save";

    public class SaveClient implements QDLFunction {
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
        public Object evaluate(Object[] objects, State state) throws Throwable{
            checkInit();
            if (!(objects[0] instanceof QDLStem)) {
                throw new BadArgException("The argument must be a stem variable",0);
            }
            QDLStem QDLStem = (QDLStem) objects[0];
            JSON jj = QDLStem.toJSON();
            if (jj.isArray()) {
                throw new BadArgException("The client is not in the expected format.", 0);
            }

            JSONObject json = (JSONObject) jj;
            // So reverse the process from the read function
                JSONObject output = new JSONObject();
                output.put("client", json); // everything else.
                OA2ClientConverter converter = (OA2ClientConverter) getEnvironment().getClientStore().getMapConverter();
                OA2Client client = converter.fromJSON(output);
                getEnvironment().getClientStore().save(client);
            return Boolean.TRUE;
        }


        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(client.) - save the client. This returns true if the operation succeeds.");
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
        public Object evaluate(Object[] objects, State state) throws Throwable{
            checkInit();
            String key = objects[0].toString();
            String regex = objects[1].toString();
            int index = 0;
            QDLStem output = new QDLStem();

           // try {
                List<OA2Client> clients = getEnvironment().getClientStore().search(key, regex, true);
                // make it in to a list
                for (OA2Client c : clients) {
                    output.put(index++ + ".", toStem(c));
                }
            /*} catch (Exception e) {
                e.printStackTrace();
            }*/
            return output;

        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(key, regex) -  search for all clients with the given key whose values satisfy the regex.");
            doxx.add("Note especially this returns a bunch of stems, one for each client that is found, so it is equivalent to a multi-read");
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
            return new int[]{0};
        }

        @Override
        public Object evaluate(Object[] objects, State state) throws Throwable{
            checkInit();
        //    try {
                return getEnvironment().getClientStore().size();
        /*    } catch (Exception e) {
                throw new QDLException("Error: COuld not determine the size of the store:" + e.getMessage(), e);
            }*/
        }


        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "() - returns a count of how many clients there are in this store.");
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
        public Object evaluate(Object[] objects, State state) throws Throwable{
            checkInit();
                Identifier id = BasicIdentifier.newID(objects[0].toString());
                getEnvironment().getClientStore().remove(id);
         return Boolean.TRUE;
        }


        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(id) - remove the client with the given identifier. Returns true if this worked.");
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
            return new int[]{0};
        }

        @Override
        public Object evaluate(Object[] objects, State state) throws Throwable{
            checkInit();
            OA2ClientConverter cc = null;
                cc = (OA2ClientConverter) getEnvironment().getClientStore().getMapConverter();
          List<Object> x = new ArrayList<>();
            x.addAll(cc.getKeys().allKeys());
            QDLStem QDLStem = new QDLStem();
            QDLStem.addList(x);
            return QDLStem;
        }


        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "() - list the keys (names of properties) for clients.");
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    protected String APPROVE_NAME = "approve";

    public class Approve implements QDLFunction {
        @Override
        public String getName() {
            return APPROVE_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1, 2};
        }

        //     cm#init('${cfg_file}', '${cfg_name}')
        //  q. := cm#search('client_id', '.*23.*')
        //   cm#approve(q.0.client_id)
        @Override
        public Object evaluate(Object[] objects, State state) throws Throwable{
            checkInit();

            Identifier id = BasicIdentifier.newID(objects[0].toString());

            Boolean toApprove = null;
            if (objects.length == 2) {
                if (!(objects[1] instanceof Boolean)) {
                    throw new BadArgException("The second argument must be a boolean.",1);
                }
                toApprove = (Boolean) objects[1];
            }

                Boolean isApproved = getEnvironment().getClientApprovalStore().isApproved(id);
                if (objects.length == 1) {
                    return isApproved;
                }
                ClientApproval approval = new ClientApproval(id);
                approval.setApproved(toApprove);
                if (toApprove) {
                    approval.setStatus(ClientApproval.Status.APPROVED);
                } else {
                    if (!isApproved) {
                        approval.setStatus(ClientApproval.Status.REVOKED);
                    }
                }
                getEnvironment().getClientApprovalStore().save(approval);
                return isApproved;
        }


        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            switch (argCount) {
                case 1:
                    doxx.add(getName() + "(id) -  This will return if the client is approved. ");
                    break;
                case 2:
                    doxx.add(getName() + "(id,true|false) -   Whether to approve or disapprove a client.");
                    doxx.add("NOTE: This returns the *previous* state before the change.");
            }
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    @Override
    public JSONObject serializeToJSON() {
        return null;
    }

    @Override
    public void deserializeFromJSON(JSONObject jsonObject) {

    }
}
