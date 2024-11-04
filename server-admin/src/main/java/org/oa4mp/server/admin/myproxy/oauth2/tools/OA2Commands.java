package org.oa4mp.server.admin.myproxy.oauth2.tools;

import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.functor.claims.OA2FunctorFactory;
import org.oa4mp.server.loader.oauth2.loader.OA2ConfigurationLoader;
import org.oa4mp.server.admin.myproxy.oauth2.Banners;
import org.oa4mp.server.admin.myproxy.oauth2.base.BaseCommands;
import org.oa4mp.server.admin.myproxy.oauth2.base.ClientStoreCommands;
import org.oa4mp.server.admin.myproxy.oauth2.base.CopyCommands;
import org.oa4mp.delegation.common.OA4MPVersion;
import edu.uiuc.ncsa.sas.SASCLIDriver;
import edu.uiuc.ncsa.sas.StringIO;
import edu.uiuc.ncsa.sas.thing.response.LogonResponse;
import edu.uiuc.ncsa.sas.webclient.Client;
import edu.uiuc.ncsa.sas.webclient.ResponseDeserializer;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.cli.*;
import edu.uiuc.ncsa.security.util.configuration.XMLConfigUtil;
import org.apache.commons.configuration.tree.ConfigurationNode;
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
    public static final String VIRTUAL_ISSUER = "vi";


    @Override
    protected void init() {
        super.init();
        components.add(PERMISSIONS);
        components.add(ADMINS);
        components.add(TOKENS);
        components.add(KEYS);
        components.add(VIRTUAL_ISSUER);
    }

    public OA2Commands(MyLoggingFacade logger) {
        super(logger);
    }

    @Override
    public String getPrompt() {
        return "oa4mp>";
    }

    protected ConfigurationLoader<? extends AbstractEnvironment> loader = null;

    @Override
    public ConfigurationLoader<? extends AbstractEnvironment> getLoader() {
        if (loader == null) {
            ConfigurationNode node =
                    XMLConfigUtil.findConfiguration(getConfigFile(), getConfigName(), getComponentName());
            loader = new OA2ConfigurationLoader<>(node, getMyLogger());
        }
        return loader;
    }

    @Override
    public void print_help() throws Exception {
        say("Need to write help");
    }

    @Override
    public ParserCommands getNewParserCommands() throws Throwable {
        OA2FunctorFactory ff = new OA2FunctorFactory(new HashMap<String, Object>(), new LinkedList<String>());
        ff.setVerboseOn(true);
        return new ParserCommands(getMyLogger(), ff);
    }

    OA2SE getOA2SE() throws Exception {
        return (OA2SE) getServiceEnvironment();
    }

    public static void main(String[] args) {
        try {
            InputLine inputLine = new InputLine(args);
            if (inputLine.hasArg("-sas")) {
                setupSAS(inputLine);
                return;
            }
            OA2Commands oa2Commands = new OA2Commands(null);
            oa2Commands.start(args); // read the command line options and such to set the state
            CLIDriver cli = new CLIDriver(oa2Commands); // actually run the driver that parses commands and passes them along
            cli.start();
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }


    protected static void setupSAS(InputLine inputLine) throws Throwable {
        Client sasClient = Client.newInstance(inputLine);
        sasClient.setResponseDeserializer(new ResponseDeserializer());
        LogonResponse logonResponse = (LogonResponse) sasClient.doLogon();
        SASCLIDriver sascliDriver = new SASCLIDriver(new StringIO(""));
        OA2Commands oa2Commands = new OA2Commands(null);
        sascliDriver.addCommands(oa2Commands);
        sascliDriver.start();
    }

    @Override
    public void useHelp() {
        say("Choose the component you wish to use.");
        say("you specify the component as use + name. Supported components are");
        say(CLIENTS + " - edit client records");
        say(CLIENT_APPROVALS + " - edit client approval records");
        say(PERMISSIONS + " - basic permission management.");
        say(ADMINS + " - create or manage administrative clients.");
        say(TOKENS + " - manage tokens created in the token exchange endpoint");
        say(VIRTUAL_ISSUER + " - manage virtual issuers");
        say("e.g.\n\nuse " + CLIENTS + "\n\nwill call up the client management component.");
        say("Type 'exit' or /q when you wish to exit the component and return to the main menu");
        say(" --> and /h prints your command history, /r runs the last command");

    }


    @Override
    public void about() {
        about(showLogo, showHeader);
    }

    public void about(boolean showBanner, boolean showHeader) {
        int width = 60;
        String banner = Banners.TIMES; // default
        if (logoName.equals("roman")) banner = Banners.ROMAN;
        if (logoName.equals("os2")) banner = Banners.OS2;
        if (logoName.equals("times")) banner = Banners.TIMES;
        if (logoName.equals("fraktur")) banner = Banners.FRAKTUR;
        if (logoName.equals("plain")) banner = Banners.PLAIN;
        if (logoName.equals("none")) {
            showBanner = false;
        }

        String stars = StringUtils.rightPad("", width + 1, "*");
        if (showBanner) {
            say(banner);
        }
        if (showHeader) {
            say(stars);
            say(padLineWithBlanks("* OA4MP CLI (Command Line Interpreter)", width) + "*");
            say(padLineWithBlanks("* Version " + OA4MPVersion.VERSION_NUMBER, width) + "*");
            say(padLineWithBlanks("* By Jeff Gaynor  NCSA", width) + "*");
            say(padLineWithBlanks("* type 'help' for a list of commands", width) + "*");
            say(padLineWithBlanks("*      'exit', 'quit' or '/q' to end this session.", width) + "*");
            say(stars);
        }
    }

    OA2ClientCommands oa2ClientCommands = null;

    @Override
    public ClientStoreCommands getNewClientStoreCommands() throws Throwable {
        if (oa2ClientCommands == null) {
            oa2ClientCommands = new OA2ClientCommands(getMyLogger(),
                    "  ",
                    getServiceEnvironment().getClientStore(),
                    getNewClientApprovalStoreCommands(),
                    getOA2SE().getPermissionStore());

            oa2ClientCommands.setRefreshTokensEnabled(getOA2SE().isRefreshTokenEnabled());
            oa2ClientCommands.setSupportedScopes(getOA2SE().getScopes());
            //       oa2ClientCommands.setUucConfiguration(getOA2SE().getUucConfiguration());
            oa2ClientCommands.setEnvironment(getOA2SE());
        }
        return oa2ClientCommands;
    }

    @Override
    public CopyCommands getNewCopyCommands() throws Throwable {
        return new CopyCommands(getMyLogger(), new OA2CopyTool(), new OA2CopyToolVerifier(), getConfigFile());
    }

    TokenStoreCommands tokenStoreCommands = null;

    protected CommonCommands getTokenCommands() throws Throwable {
        if (tokenStoreCommands == null) {
            tokenStoreCommands = new TokenStoreCommands(getMyLogger(), "  ", getOA2SE().getTxStore());
            tokenStoreCommands.setEnvironment(getOA2SE());
        }

        return tokenStoreCommands;
    }

    VICommands VICommands;

    protected VICommands getVOCommands() throws Throwable {
        if (VICommands == null) {
            VICommands = new VICommands(getMyLogger(), "  ", getOA2SE().getVOStore());
            VICommands.setEnvironment(getOA2SE());
        }
        return VICommands;
    }

    TransactionStoreCommands transactionStoreCommands = null;

    @Override
    protected CommonCommands getTransactionCommands() throws Throwable {
        if (transactionStoreCommands == null) {
            transactionStoreCommands = new TransactionStoreCommands(getMyLogger(),
                    "  ",
                    getOA2SE());
            transactionStoreCommands.setEnvironment(getOA2SE());
        }

        return transactionStoreCommands;
    }


    OA2AdminClientCommands oa2AdminClientCommands = null;

    public OA2AdminClientCommands getAdminClientCommands() throws Throwable {
        if (oa2AdminClientCommands == null) {
            oa2AdminClientCommands = new OA2AdminClientCommands(getMyLogger(),
                    "  ",
                    getOA2SE().getAdminClientStore(),
                    getNewClientApprovalStoreCommands(),
                    getOA2SE().getPermissionStore(),
                    getOA2SE().getClientStore());
            oa2AdminClientCommands.setEnvironment(getOA2SE());
        }
        return oa2AdminClientCommands;
    }

    OA2PermissionCommands oa2PermissionCommands = null;

    public OA2PermissionCommands getPermissionCommands() throws Throwable {
        if (oa2PermissionCommands == null) {
            oa2PermissionCommands = new OA2PermissionCommands(getMyLogger(), "  ", getOA2SE().getPermissionStore());
            oa2PermissionCommands.setEnvironment(getOA2SE());
        }
        return oa2PermissionCommands;
    }

    @Override
    public boolean use(InputLine inputLine) throws Throwable {
        CommonCommands commands = null;
        if (inputLine.hasArg(ADMINS)) {
            commands = getAdminClientCommands();
        }
  /*      if (inputLine.hasArg(KEYS)) {
            commands = new SigningCommands(getOA2SE());
        }*/
        if (inputLine.hasArg(PERMISSIONS)) {
            commands = getPermissionCommands();
        }
        if (inputLine.hasArg(TOKENS)) {
            commands = getTokenCommands();
        }
        if (inputLine.hasArg(VIRTUAL_ISSUER)) {
            commands = getVOCommands();
        }
        if (commands != null) {
            return switchOrRun(inputLine, commands);
        }

        if (super.use(inputLine)) {
            return true;
        }
        say("(no such component)");
        return false;
    }

    @Override
    public void bootstrap() throws Throwable {

    }

    HelpUtil helpUtil = new HelpUtil();

    @Override
    public HelpUtil getHelpUtil() {
        return helpUtil;
    }

    @Override
    public void setLoader(ConfigurationLoader<? extends AbstractEnvironment> loader) {
        this.loader = loader;
    }

    @Override
    protected ConfigurationLoader<? extends AbstractEnvironment> figureOutLoader(String fileName, String configName) throws Throwable {
        ConfigLoaderTool configLoaderTool = new ConfigLoaderTool();
        return configLoaderTool.figureOutServerLoader(fileName, configName, getComponentName());
    }
}
