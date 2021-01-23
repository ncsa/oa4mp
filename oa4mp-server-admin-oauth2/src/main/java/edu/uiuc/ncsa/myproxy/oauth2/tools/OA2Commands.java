package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.functor.claims.OA2FunctorFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.server.BaseCommands;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ClientStoreCommands;
import edu.uiuc.ncsa.myproxy.oa4mp.server.CopyCommands;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.core.util.LoggingConfigLoader;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;
import edu.uiuc.ncsa.security.util.cli.CommonCommands;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import edu.uiuc.ncsa.security.util.cli.ParserCommands;
import org.apache.commons.lang.StringUtils;

import java.util.HashMap;
import java.util.LinkedList;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/3/14 at  1:23 PM
 */
public class OA2Commands extends BaseCommands {
    public static final String PERMISSIONS = "permissions";
    public static final String ADMINS = "admins";
    public static final String TOKENS = "tokens";
    public static final String KEYS = "keys";
  //  public static final String JSON = "json";

    public OA2Commands(MyLoggingFacade logger) {
        super(logger);
    }

    @Override
    public String getPrompt() {
        return "oa2>";
    }

    @Override
    public ConfigurationLoader<? extends AbstractEnvironment> getLoader() {
        return new OA2ConfigurationLoader<>(getConfigurationNode(), getMyLogger());
    }

    @Override
    public void print_help(InputLine inputLine) throws Exception{
           say("Need to write help");
    }

    @Override
    public ParserCommands getNewParserCommands() throws Exception {
        OA2FunctorFactory ff = new OA2FunctorFactory(new HashMap<String, Object>(), new LinkedList<String>());
        ff.setVerboseOn(true);
        return new ParserCommands(getMyLogger(), ff);
    }

    OA2SE getOA2SE() throws Exception {
        return (OA2SE) getServiceEnvironment();
    }

    public static void main(String[] args) {
        try {
            OA2Commands oa2Commands = new OA2Commands(null);
            oa2Commands.start(args); // read the command line options and such to set the state
            CLIDriver cli = new CLIDriver(oa2Commands); // actually run the driver that parses commands and passes them along
            cli.start();
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }

    @Override
    public void useHelp() {
        say("Choose the component you wish to use.");
        say("you specify the component as use + name. Supported components are");
        say(CLIENTS + " - edit client records");
        say(CLIENT_APPROVALS + " - edit client approval records");
        say(COPY + " - copy an entire store.");
        say(KEYS + " - create a set of signing keys.");
        say(PERMISSIONS + " - basic permission management.");
        say(ADMINS + " - create or manage administrative clients.");
        say(PARSER_COMMAND + " - write/debug scripts from the command line.");
        say(TOKENS + " - manage tokens created in the token exchange endpoint");
//        say(JSON + " - enter JSON snippets to be used by the system in client configurations.\n");
        say("e.g.\n\nuse " + CLIENTS + "\n\nwill call up the client management component.");
        say("Type 'exit' when you wish to exit the component and return to the main menu");
        say(" --> and /h prints your command history, /r runs the last command");

    }

    @Override
    public void about() {
        int width = 60;
        String stars = StringUtils.rightPad("", width + 1, "*");
        say(stars);
        say(padLineWithBlanks("* OA4MP2 OAuth 2/OIDC CLI (Command Line Interpreter)", width) + "*");
        say(padLineWithBlanks("* Version " + LoggingConfigLoader.VERSION_NUMBER, width) + "*");
        say(padLineWithBlanks("* By Jeff Gaynor  NCSA", width) + "*");
        say(padLineWithBlanks("*  (National Center for Supercomputing Applications)", width) + "*");
        say(padLineWithBlanks("*", width) + "*");
        say(padLineWithBlanks("* type 'help' for a list of commands", width) + "*");
        say(padLineWithBlanks("*      'exit' or 'quit' to end this session.", width) + "*");
        say(stars);
    }
    OA2ClientCommands oa2ClientCommands = null;
    @Override
    public ClientStoreCommands getNewClientStoreCommands() throws Exception {
        if(oa2ClientCommands == null) {
            oa2ClientCommands = new OA2ClientCommands(getMyLogger(),
                    "  ",
                    getServiceEnvironment().getClientStore(),
                    getServiceEnvironment().getClientApprovalStore());
            oa2ClientCommands.setRefreshTokensEnabled(getOA2SE().isRefreshTokenEnabled());
            oa2ClientCommands.setSupportedScopes(getOA2SE().getScopes());
        }
        return oa2ClientCommands;
    }

    @Override
    public CopyCommands getNewCopyCommands() throws Exception {
        return new CopyCommands(getMyLogger(), new OA2CopyTool(), new OA2CopyToolVerifier(), getConfigFile());
    }
    TokenStoreCommands tokenStoreCommands = null;
    protected CommonCommands getTokenCommands() throws Exception{
        if(tokenStoreCommands == null){
            tokenStoreCommands = new TokenStoreCommands(getMyLogger(), "  ", getOA2SE().getTxStore());
        }

        return tokenStoreCommands;
    }



    TransactionStoreCommands transactionStoreCommands = null;
    @Override
    protected CommonCommands getTransactionCommands() throws Exception{
        if(transactionStoreCommands == null){
            transactionStoreCommands = new TransactionStoreCommands(getMyLogger(), "  ", getOA2SE().getTransactionStore());
        }

        return transactionStoreCommands;
    }

    OA2AdminClientCommands oa2AdminClientCommands = null;
    public OA2AdminClientCommands getAdminClientCommands() throws Exception {
        if(oa2AdminClientCommands == null) {
            oa2AdminClientCommands =  new OA2AdminClientCommands(getMyLogger(),
                    "  ",
                    getOA2SE().getAdminClientStore(),
                    getOA2SE().getClientApprovalStore(),
                    getOA2SE().getPermissionStore());
        }
        return  oa2AdminClientCommands;
    }

    OA2PermissionCommands oa2PermissionCommands = null;
    public OA2PermissionCommands getPermissionCommands() throws Exception {
        if(oa2PermissionCommands == null) {
            oa2PermissionCommands =  new OA2PermissionCommands(getMyLogger(), "  ", getOA2SE().getPermissionStore());
        }
        return oa2PermissionCommands;
    }

    @Override
    public boolean use(InputLine inputLine) throws Exception {
        CommonCommands commands = null;
        if (inputLine.hasArg(ADMINS)) {
            commands = getAdminClientCommands();
        }
        if (inputLine.hasArg(KEYS)) {
            commands = new SigningCommands(getOA2SE());
        }
        if (inputLine.hasArg(PERMISSIONS)) {
            commands = getPermissionCommands();
        }
        if(inputLine.hasArg(TOKENS)){
            commands = getTokenCommands();
        }
        if (commands != null) {
            CLIDriver cli = new CLIDriver(commands);
            cli.setEnv(getGlobalEnv());
            cli.start();
            return true;
        }

        if (super.use(inputLine)) {
            return true;
        }

        return false;
    }
}
