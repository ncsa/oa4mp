package edu.uiuc.ncsa.myproxy.oa4mp.qdl.cm;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientConverter;
import edu.uiuc.ncsa.qdl.exceptions.QDLException;
import edu.uiuc.ncsa.qdl.extensions.QDLFunction;
import edu.uiuc.ncsa.qdl.variables.StemVariable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.util.configuration.ConfigUtil;
import net.sf.json.JSON;
import net.sf.json.JSONObject;
import org.apache.commons.configuration.tree.ConfigurationNode;

import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/31/20 at  11:07 AM
 */
public class ClientCommands {
    public MyLoggingFacade getLogger() {
        return logger;
    }

    public void setLogger(MyLoggingFacade logger) {
        this.logger = logger;
    }

    MyLoggingFacade logger = null;

    public ConfigurationLoader<? extends AbstractEnvironment> getLoader() {
        return new OA2ConfigurationLoader<OA2SE>(getConfigurationNode(), getLogger());
    }

    public ConfigurationNode getConfigurationNode() {
        return configurationNode;
    }

    public void setConfigurationNode(ConfigurationNode configurationNode) {
        this.configurationNode = configurationNode;
    }

    ConfigurationNode configurationNode;

    public OA2SE getEnvironment() throws Exception {
        if (environment == null) {
            environment = (OA2SE) getLoader().load();
        }
        return environment;
    }

    OA2SE environment = null;
    boolean initCalled = false;

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

    //  cm#init('/home/ncsa/dev/csd/config/servers.xml', 'localhost:oa4mp.oa2.mariadb')
    //    cm#read('ashigaru:command.line2');
    public class InitMethod implements QDLFunction {
        @Override
        public String getName() {
            return "init";
        }

        @Override
        public int[] getArgCount() {
            return new int[]{2};
        }

        @Override
        public Object evaluate(Object[] objects) {
            init(objects[0].toString(), objects[1].toString());
            return true;
        }


        @Override
        public List<String> getDocumentation() {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(file, name) - reads the configuration file and then loads the configuration with the given name. ");
            doxx.add("This must be called before any other function.");
            return doxx;
        }
    }

    public class ReadClient implements QDLFunction {
        @Override
        public String getName() {
            return "read";
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public Object evaluate(Object[] objects) {
            try {
                if (!initCalled) {
                    throw new IllegalStateException("Error: You must call init before calling this function");
                }
                OA2Client client = (OA2Client) getEnvironment().getClientStore().get(BasicIdentifier.newID(objects[0].toString()));
                return toStem(client);
            } catch (Throwable t) {
                throw new QDLException("Error: Could not find the client with id \"" + objects[0].toString() + "\"");
            }
        }


        @Override
        public List<String> getDocumentation() {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(id) - read the client with the given identifier. This will return a stem representation of the client. ");
            doxx.add("Be sure you have called the init function first or this will fail.");
            return doxx;
        }
    }

    protected StemVariable toStem(OA2Client client) throws Exception {
        if (client == null) {
            return new StemVariable();
        }
        OA2ClientConverter converter = (OA2ClientConverter) getEnvironment().getClientStore().getMapConverter();
        JSONObject jsonObject = new JSONObject();
        converter.toJSON(client, jsonObject);
        StemVariable output = new StemVariable();
        if (jsonObject.isEmpty()) {
            return output;
        }
        // The serialization form is {"client":...}. We want this to look more natural
        // It is used by RFC 7591, so we have to twiddle that
        JSONObject j2 = jsonObject.getJSONObject("client");

        output.fromJSON(j2);
        return output;
    }

    public class SaveClient implements QDLFunction {
        @Override
        public String getName() {
            return "save";
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        // cm#init('${cfg_file}', '${cfg_name}')
        //  client. := cm#read('${id}')
        // cm#save(client.)
        @Override
        public Object evaluate(Object[] objects) {
            if (!initCalled) {
                throw new IllegalStateException("Error: You must call init before calling this function");
            }

            if (!(objects[0] instanceof StemVariable)) {
                throw new IllegalArgumentException("Error: The argument must be a stem variable");
            }
            StemVariable stemVariable = (StemVariable) objects[0];
            JSON jj = stemVariable.toJSON();
            if (jj.isArray()) {
                throw new IllegalArgumentException("Error: The client is not in the expected format.");
            }

            JSONObject json = (JSONObject) jj;
            // So reverse the process from the read function
            try {
                JSONObject output = new JSONObject();
                //      output.put("cfg", json.getJSONObject("cfg"));
                //     json.remove("cfg");
                output.put("client", json); // everything else.
                OA2ClientConverter converter = (OA2ClientConverter) getEnvironment().getClientStore().getMapConverter();
                OA2Client client = converter.fromJSON(output);
                getEnvironment().getClientStore().save(client);
            } catch (Throwable t) {
                if (t instanceof RuntimeException) {
                    throw (RuntimeException) t;
                }
                throw new QDLException("Error: could not save the client:" + t.getMessage(), t);
            }
            return Boolean.TRUE;
        }


        @Override
        public List<String> getDocumentation() {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(client.) - save the client. This returns true if the operation succeeds.");
            doxx.add("Be sure you have called the init function first or this will fail.");
            return doxx;
        }
    }

    public class Search implements QDLFunction {
        @Override
        public String getName() {
            return "search";
        }

        @Override
        public int[] getArgCount() {
            return new int[]{2};
        }

        @Override
        public Object evaluate(Object[] objects) {
            if (!initCalled) {
                throw new IllegalStateException("Error: You must call init before calling this function");
            }

            String key = objects[0].toString();
            String regex = objects[1].toString();
            int index = 0;
            StemVariable output = new StemVariable();

            try {
                List<OA2Client> clients = getEnvironment().getClientStore().search(key, regex, true);
                for (OA2Client c : clients) {
                    output.put(index + ".", toStem(c));
                    index++;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            return output;

        }

        @Override
        public List<String> getDocumentation() {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(key, regex) -  search for all clients with the given key whose values satisfy the regex.");
            doxx.add("Be sure you have called the init function first or this will fail.");
            return doxx;
        }
    }

    public class Size implements QDLFunction {
        @Override
        public String getName() {
            return "size";
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0};
        }

        @Override
        public Object evaluate(Object[] objects) {
            if (!initCalled) {
                throw new IllegalStateException("Error: You must call init before calling this function");
            }

            try {
                return new Long(getEnvironment().getClientStore().size());
            } catch (Exception e) {
                throw new QDLException("Error: COuld not determine the size of the store:" + e.getMessage(), e);
            }
        }


        @Override
        public List<String> getDocumentation() {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "() - returns a count of how many clients there are in this store.");
            doxx.add("Be sure you have called the init function first or this will fail.");
            return doxx;
        }
    }

    public class Remove implements QDLFunction {
        @Override
        public String getName() {
            return "remove";
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public Object evaluate(Object[] objects) {
            if (!initCalled) {
                throw new IllegalStateException("Error: You must call init before calling this function");
            }
            try {
                Identifier id = BasicIdentifier.newID(objects[0].toString());
                getEnvironment().getClientStore().remove(id);
            } catch (Throwable e) {
                throw new QDLException("Error: Could not remove object with id " + objects[0] + ":" + e.getMessage());
            }
            return Boolean.TRUE;
        }


        @Override
        public List<String> getDocumentation() {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(id) - remove the client with the figen identifier. Returns true if this worked.");
            doxx.add("Be sure you have called the init function first or this will fail.");
            return doxx;
        }
    }

    public class Keys implements QDLFunction {
        @Override
        public String getName() {
            return "keys";
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0};
        }

        @Override
        public Object evaluate(Object[] objects) {
            if (!initCalled) {
                throw new IllegalStateException("Error: You must call init before calling this function");
            }
            OA2ClientConverter cc = null;
            try {
                cc = (OA2ClientConverter) getEnvironment().getClientStore().getMapConverter();
            } catch (Exception e) {
                e.printStackTrace();
            }
            List<Object> x = new ArrayList<>();
            x.addAll(cc.getKeys().allKeys());
            StemVariable stemVariable = new StemVariable();
            stemVariable.addList(x);
            return stemVariable;
        }


        @Override
        public List<String> getDocumentation() {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "() - list the keys (names of properties) for clients.");
            doxx.add("Be sure you have called the init function first or this will fail.");
            return doxx;
        }
    }

    public class Approve implements QDLFunction {
        @Override
        public String getName() {
            return "approve";
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1,2};
        }
        //     cm#init('${cfg_file}', '${cfg_name}')
             //  q. := cm#search('client_id', '.*23.*')
        //   cm#approve(q.0.client_id)
        @Override
        public Object evaluate(Object[] objects) {
            if (!initCalled) {
                throw new IllegalStateException("Error: You must call init before calling this function");
            }
            
            Identifier id = BasicIdentifier.newID(objects[0].toString());

            Boolean toApprove = null;
            if (objects.length == 2) {
                if (!(objects[1] instanceof Boolean)) {
                    throw new IllegalArgumentException("Error: The second argument must be a boolean.");
                }
                toApprove = (Boolean) objects[1];
            }
            try {

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
            } catch (Exception e) {
                e.printStackTrace();
            }
            return Boolean.FALSE;
        }


        @Override
        public List<String> getDocumentation() {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(id[,true|false) -  If one argument, this will return if the client is approved. " +
                    "Otherwise, supply whether or not to approve this client. The returned value is the previous value.");
            doxx.add("Be sure you have called the init function first or this will fail.");
            return doxx;
        }
    }
}
