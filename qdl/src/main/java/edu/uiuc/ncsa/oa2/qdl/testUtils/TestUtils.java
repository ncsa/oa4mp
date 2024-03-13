package edu.uiuc.ncsa.oa2.qdl.testUtils;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.ClientUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientKeys;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Constants;
import edu.uiuc.ncsa.qdl.extensions.QDLFunction;
import edu.uiuc.ncsa.qdl.extensions.QDLModuleMetaClass;
import edu.uiuc.ncsa.qdl.state.State;
import edu.uiuc.ncsa.qdl.variables.QDLStem;
import edu.uiuc.ncsa.security.util.configuration.XMLConfigUtil;
import net.sf.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client.USE_SERVER_DEFAULT;

/**
 * This is mostly for testing. It allows access to utilities the server uses to verify
 * that certain operations are done right, such as computing token lifetimes.
 * <p>Created by Jeff Gaynor<br>
 * on 3/11/24 at  7:33 AM
 */
public class TestUtils implements QDLModuleMetaClass {
    OA2ClientKeys oa2ClientKeys = new OA2ClientKeys();
    public static final String COMPUTE_IDT_LIFETIME = "idt_lifetime";

    public class ComputeIDTLifetime implements QDLFunction {
        @Override
        public String getName() {
            return COMPUTE_IDT_LIFETIME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{2, 3};
        }

        @Override
        public Object evaluate(Object[] objects, State state) throws Throwable {
            // args are server_defaults., client.
            // args are server_defaults., client., requested_lifetime
            long requestedLifetime = checkArgs(objects, getName());
            QDLStem serverDefaults = (QDLStem) objects[0];
            QDLStem client = (QDLStem) objects[1];

            return ClientUtils.computeTokenLifetime(1000*serverDefaults.getLong(OA2Constants.MAX_ID_TOKEN_LIFETIME),
                    1000*serverDefaults.getLong(OA2Constants.ID_TOKEN_LIFETIME),
                    1000*client.getLong(OA2Constants.ID_TOKEN_LIFETIME),
                    1000*client.getLong(OA2Constants.MAX_ID_TOKEN_LIFETIME),
                    getClientCfgLifetime(client, "identity"),
                    requestedLifetime);
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            return getLifetimeDoc(getName(), argCount);
        }
    }

    @Override
    public JSONObject serializeToJSON() {
        return new JSONObject();
    }

    @Override
    public void deserializeFromJSON(JSONObject json) {

    }

    protected Long getClientCfgLifetime(QDLStem client, String handlerName) {
        if (!client.containsKey(oa2ClientKeys.cfg())) return null;
        QDLStem cfg = client.getStem(oa2ClientKeys.cfg());
        if (!cfg.containsKey("tokens")) return null;
        QDLStem tokens = cfg.getStem("tokens");
        if (!tokens.containsKey(handlerName)) return null;
        QDLStem handler = tokens.getStem(handlerName);
        if (!handler.containsKey("lifetime")) return null;
        return 1000*handler.getLong("lifetime");

    }

    public static final String COMPUTE_AT_LIFETIME = "at_lifetime";

    public class ComputeATLifetime implements QDLFunction {
        @Override
        public String getName() {
            return COMPUTE_AT_LIFETIME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{2, 3};
        }

        @Override
        public Object evaluate(Object[] objects, State state) throws Throwable {
            long requestedLifetime = checkArgs(objects, getName());
            QDLStem serverDefaults = (QDLStem) objects[0];
            QDLStem client = (QDLStem) objects[1];

            return ClientUtils.computeTokenLifetime(1000*serverDefaults.getLong(OA2Constants.MAX_ACCESS_TOKEN_LIFETIME),
                    1000*serverDefaults.getLong(OA2Constants.ACCESS_TOKEN_LIFETIME),
                    1000*client.getLong(oa2ClientKeys.atLifetime()),
                    1000*client.getLong(OA2Constants.MAX_ACCESS_TOKEN_LIFETIME), // used in the CM
                    getClientCfgLifetime(client, "access"),
                    requestedLifetime);
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            return getLifetimeDoc(getName(), argCount);
        }
    }

    public static final String COMPUTE_RT_LIFETIME = "rt_lifetime";

    public class ComputeRTLifetime implements QDLFunction {
        @Override
        public String getName() {
            return COMPUTE_RT_LIFETIME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{2, 3};
        }

        @Override
        public Object evaluate(Object[] objects, State state) throws Throwable {
            long requestedLifetime = checkArgs(objects, getName());
            QDLStem serverDefaults = (QDLStem) objects[0];
            QDLStem client = (QDLStem) objects[1];
            return ClientUtils.computeTokenLifetime(1000*serverDefaults.getLong(OA2Constants.MAX_REFRESH_LIFETIME),
                    1000*serverDefaults.getLong(OA2Constants.REFRESH_LIFETIME),
                    1000*client.getLong(oa2ClientKeys.rtLifetime()),
                    1000*client.getLong(OA2Constants.MAX_REFRESH_LIFETIME),
                    getClientCfgLifetime(client, "refresh"),
                    requestedLifetime);

        }

        @Override
        public List<String> getDocumentation(int argCount) {
            return getLifetimeDoc(getName(), argCount);
        }
    }

    /**
     * Checks that the first two elements are stems and if a 3 arg array, returns
     * the last as a long or the {@link edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client#USE_SERVER_DEFAULT}.
     *
     * @param objects
     * @param name
     * @return
     */
    protected long checkArgs(Object[] objects, String name) {
        if (!(objects[0] instanceof QDLStem)) {
            throw new IllegalArgumentException(name + "(0) must be a stem, got a " + (objects[0] == null ? "null":objects[0].getClass().getSimpleName()));
        }
        if (!(objects[1] instanceof QDLStem)) {
            throw new IllegalArgumentException(name + "(1) must be a stem, got a " + (objects[1]==null?"null":objects[1].getClass().getSimpleName()));
        }

        return objects.length == 3 ? (Long) objects[2] : USE_SERVER_DEFAULT;
    }

    protected List<String> getLifetimeDoc(String name, int argCount) {
        List<String> d = new ArrayList<>();
        switch (argCount) {
            case 2:
                d.add(name + "(server_defaults., client.) = compute the token lifetime using server defaults and client configuration.");
                d.add("");

                break;
            case 3:
                d.add(name + "(server_defaults., client., requested) = compute the token lifetime using server defaults, client configuration and request lifetime");
                d.add("This applies all policies to the arguments for the server ");

        }
        d.add("Arguments are:");
        d.add("server_defaults. = the server defaults from the Client Management endpoint that lists all token lifetimes, maxes etc.");
        d.add("client. = the configuration for this client from the Client Management endpoint.");
        if (argCount == 3) {
            d.add("requested = the explicit requested lifetime in the request. This overrides server and client configurations but is");
            d.add("            restricted by the maxima allowed.");
        }
        return d;
    }

    public static final String COMPUTE_GRACE_PERIOD = "grace_period";
    public class ComputeGracePeriod implements QDLFunction{
        @Override
        public String getName() {
            return COMPUTE_GRACE_PERIOD;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{2};
        }

        /**
         * Recreates the logic from the server, but cannot access it since that requires access to the
         * current server state in {@link edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE}. Therefore, get this
         * from the client management endpoint as the server defaults and use those.
         * @param objects
         * @param state
         * @return
         * @throws Throwable
         */
        @Override
        public Object evaluate(Object[] objects, State state) throws Throwable {
            checkArgs(objects, getName()); // don't need output
            QDLStem serverDefaults = (QDLStem) objects[0];
            QDLStem client = (QDLStem) objects[1];
            if(serverDefaults.getLong(OA2ConfigurationLoader.REFRESH_TOKEN_GRACE_PERIOD_TAG) == OA2ConfigurationLoader.REFRESH_TOKEN_GRACE_PERIOD_DISABLED){
                return 0L;
            }
            if(client.getLong(oa2ClientKeys.rtGracePeriod()) == OA2ConfigurationLoader.REFRESH_TOKEN_GRACE_PERIOD_USE_SERVER_DEFAULT){
               return serverDefaults.getLong(OA2ConfigurationLoader.REFRESH_TOKEN_GRACE_PERIOD_TAG);
            }
            return client.getLong(oa2ClientKeys.rtGracePeriod());
            /*
                    if (!oa2SE.isRTGracePeriodEnabled()) {
            return 0L; // means no grace period.
        }
        if (client.getRtGracePeriod() == OA2ConfigurationLoader.REFRESH_TOKEN_GRACE_PERIOD_USE_SERVER_DEFAULT) {
            return oa2SE.getRtGracePeriod();
        }
        return client.getRtGracePeriod();
             */
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> d = new ArrayList<>();
            d.add(getName() + "(server_defaults., client.) = compute the refresh token grace period ");
            return d;
        }
    }

    public static final String TIME_TO_LONG = "time_to_long";
    public class TimeToLong implements QDLFunction{
        @Override
        public String getName() {
            return TIME_TO_LONG;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) throws Throwable {
            return convert(objects[0]);
        }

        protected Object convert(Object object){
            if(object instanceof String){
                return convertSingle((String)object);
            }
            if(object instanceof QDLStem){
                QDLStem stem = (QDLStem) object;
                QDLStem outStem = new QDLStem();
                for(Object key : stem.keySet()){
                    outStem.putLongOrString(key, convert(stem.get(key)));
                }
                return outStem;
            }
            return object; // do nothing.
        }
        Pattern pattern = Pattern.compile("^[0-9]*$");

        long convertSingle(String x){
            return XMLConfigUtil.getValueSecsOrMillis(x, !pattern.matcher(x).matches()); // only digits assumed to be ms
        }
        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> d = new ArrayList<>();
               d.add(getName() + "(arg | arg.) - convert to milliseconds");
               d.add("This takes a standard OA4MP time like 3 days and converts it to milliseconds.");
               d.add("If there are no units, it is assumed to be in milliseconds.");
               d.add("non-strings are not converted");
               d.add("E.g.");
               d.add(getName()+"(3)  returns 3 milliseconds");
               d.add(getName()+"(3 sec.)  returns 3000 milliseconds");
            return d;
        }
    }
}
