package edu.uiuc.ncsa.oa2.qdl;

import edu.uiuc.ncsa.myproxy.oauth2.tools.OA2CLCCommands;
import edu.uiuc.ncsa.myproxy.oauth2.tools.OA2CommandLineClient;
import edu.uiuc.ncsa.qdl.extensions.QDLFunction;
import edu.uiuc.ncsa.qdl.state.State;
import edu.uiuc.ncsa.qdl.variables.QDLNull;
import edu.uiuc.ncsa.qdl.variables.StemVariable;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.util.cli.InputLine;

import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 7/22/21 at  10:41 AM
 */
public class CLC {
    OA2CLCCommands clcCommands;

    boolean initCalled = false;

    protected void checkInit() {
        if ((clcCommands == null ) || !initCalled) {
            throw new IllegalStateException("Error: You must call " + INIT_NAME + " before calling this function");
        }
    }

    protected StemVariable getTokens(){
        StemVariable result = new StemVariable();

        StemVariable at = new StemVariable();

        at.fromJSON(clcCommands.getDummyAsset().getAccessToken().toJSON());
        try{
            StemVariable jwt = new StemVariable();
            jwt.fromJSON(clcCommands.resolveFromToken(clcCommands.getDummyAsset().getAccessToken(), false));
            at.put("jwt", jwt);
        }catch(Throwable t){

        }
        result.put("access_token", at);
        if(clcCommands.getDummyAsset().hasRefreshToken()){
            StemVariable rt = new StemVariable();
            rt.fromJSON(clcCommands.getDummyAsset().getRefreshToken().toJSON());
            try{
                StemVariable jwt = new StemVariable();
                jwt.fromJSON(clcCommands.resolveFromToken(clcCommands.getDummyAsset().getRefreshToken(), false));
                rt.put("jwt", jwt);
            }catch(Throwable t){

            }
            result.put("refresh_token", rt);
        }
        return result;
    }
    protected String DUMMY_ARG = "dummy"; // when creating input lines, need dummy arg for method name
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
        public Object evaluate(Object[] objects, State state) {
            try {
                clcCommands = new OA2CLCCommands(false, state.getLogger(), new OA2CommandLineClient(state.getLogger()));
                clcCommands.load(new InputLine(DUMMY_ARG + " " + objects[1].toString() + "  " + objects[0].toString()));
                initCalled = true;
            } catch (Exception e) {
                state.getLogger().error("error initializing client", e);
                initCalled = false;
                clcCommands = null;
                if (DebugUtil.isEnabled()) {
                    e.printStackTrace();
                    ;
                }
                return false;
            }
            return true;
        }


        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(name, file) - reads the configuration file and then loads the configuration with the given name. ");
            doxx.add("This sets the configuration and name. ");
            doxx.add("This must be called before any other function.");
            return doxx;
        }
    }

    protected String GRANT_NAME = "grant";

    public class Grant implements QDLFunction {
        @Override
        public String getName() {
            return GRANT_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0, 1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            try {
                if (objects.length == 0) {

                    clcCommands.grant(new InputLine(DUMMY_ARG));
                }
                if (objects.length == 1) {
                    clcCommands.grant(new InputLine(DUMMY_ARG + " " + objects[0]));
                }
                StemVariable g = new StemVariable();

                g.fromJSON(clcCommands.getGrant().toJSON());
                return g;
            } catch (Exception e) {
                state.getLogger().error("error getting grant", e);
                if (DebugUtil.isEnabled()) {
                    e.printStackTrace();
                }
                return QDLNull.getInstance();
            }
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "([grant]) - set the current grant.");
            if (argCount == 0) {
                doxx.add(getName() + "() - set the grant from the clipboard");
            }
            if (argCount == 1) {
                doxx.add(getName() + "(grant) - set the grant");

            }
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    protected String ACCESS_NAME = "access";

    public class Access implements QDLFunction {
        @Override
        public String getName() {
            return ACCESS_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            checkInit();
                try {
                    clcCommands.access(new InputLine(DUMMY_ARG));
                    return getTokens();
                } catch (Exception e) {
                    state.getLogger().error("error getting access token", e);
                    if (DebugUtil.isEnabled()) {
                        e.printStackTrace();
                    }
                }
            return QDLNull.getInstance();
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + " get the access token.");
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    protected String URI_NAME = "uri";

    public class CreateURI implements QDLFunction {
        @Override
        public String getName() {
            return URI_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {  
            checkInit();
            try {
               clcCommands.uri(new InputLine(DUMMY_ARG));
                return clcCommands.getCurrentURI().toString();
            } catch (Exception e) {
                if (DebugUtil.isEnabled()) {
                    e.printStackTrace();
                }
            }
            return QDLNull.getInstance();
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + " create the uri. This is returned and, if possible, copied to the clipboard.");
            doxx.add(checkInitMessage);
            return doxx;
        }
    }

    protected String REFRESH_NAME = "refresh";
    public class Refresh implements QDLFunction{
        @Override
        public String getName() {
            return REFRESH_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            checkInit();
            try {
                clcCommands.refresh(new InputLine(DUMMY_ARG));
                return getTokens();
            } catch (Exception e) {

                if(DebugUtil.isEnabled()) {
                    e.printStackTrace();
                }
            }
            return QDLNull.getInstance();
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            return null;
        }
    }
    protected String EXCHANGE_NAME = "exchange";
    protected String REVOKE_NAME = "revoke";
    protected String DEVICE_FLOW_NAME = "df";
    protected String USER_INFO_NAME = "user_info";
    protected String TOKENS_NAME = "tokens";


}
