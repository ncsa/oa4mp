package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.functor.claims.OA2FunctorFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oauth2.Banners;
import edu.uiuc.ncsa.myproxy.oauth2.base.BaseCommands;
import edu.uiuc.ncsa.myproxy.oauth2.base.ClientStoreCommands;
import edu.uiuc.ncsa.myproxy.oauth2.base.CopyCommands;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.core.util.LoggingConfigLoader;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.cli.*;
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
    public static final String VIRTUAL_ORGANIZATION = "vo";
    //  public static final String JSON = "json";


    @Override
    protected void init() {
        super.init();
        components.add(PERMISSIONS);
        components.add(ADMINS);
        components.add(TOKENS);
        components.add(KEYS);
        components.add(VIRTUAL_ORGANIZATION);
    }

    public OA2Commands(MyLoggingFacade logger) {
        super(logger);
    }

    @Override
    public String getPrompt() {
        return "oa4mp>";
    }

    @Override
    public ConfigurationLoader<? extends AbstractEnvironment> getLoader() {
        return new OA2ConfigurationLoader<>(getConfigurationNode(), getMyLogger());
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
        say(PERMISSIONS + " - basic permission management.");
        say(ADMINS + " - create or manage administrative clients.");
        say(TOKENS + " - manage tokens created in the token exchange endpoint");
        say(VIRTUAL_ORGANIZATION + " - manage virtual organizations");
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
        String banner=Banners.TIMES; // default
        if(logoName.equals("roman")) banner = Banners.ROMAN;
        if(logoName.equals("os2")) banner = Banners.OS2;
        if(logoName.equals("times")) banner = Banners.TIMES;
        if(logoName.equals("fraktur")) banner = Banners.FRAKTUR;
        if(logoName.equals("plain")) banner = Banners.PLAIN;
        if(logoName.equals("none")) {showBanner = false;}

        String stars = StringUtils.rightPad("", width + 1, "*");
        if(showBanner){say(banner);}
        if(showHeader) {
            say(stars);
            say(padLineWithBlanks("* OA4MP CLI (Command Line Interpreter)", width) + "*");
            say(padLineWithBlanks("* Version " + LoggingConfigLoader.VERSION_NUMBER, width) + "*");
            say(padLineWithBlanks("* By Jeff Gaynor  NCSA", width) + "*");
            say(padLineWithBlanks("* type 'help' for a list of commands", width) + "*");
            say(padLineWithBlanks("*      'exit', 'quit' or '/q' to end this session.", width) + "*");
            say(stars);
        }
    }

    OA2ClientCommands oa2ClientCommands = null;

    @Override
    public ClientStoreCommands getNewClientStoreCommands() throws Throwable{
        if (oa2ClientCommands == null) {
            oa2ClientCommands = new OA2ClientCommands(getMyLogger(),
                    "  ",
                    getServiceEnvironment().getClientStore(),
                    getNewClientApprovalStoreCommands());
            oa2ClientCommands.setRefreshTokensEnabled(getOA2SE().isRefreshTokenEnabled());
            oa2ClientCommands.setSupportedScopes(getOA2SE().getScopes());
            oa2ClientCommands.setUucConfiguration(getOA2SE().getUucConfiguration());
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
        }

        return tokenStoreCommands;
    }

    VOCommands voCommands;

    protected VOCommands getVOCommands() throws Throwable {
        if (voCommands == null) {
            voCommands = new VOCommands(getMyLogger(), "  ", getOA2SE().getVOStore());
        }
        return voCommands;
    }

    TransactionStoreCommands transactionStoreCommands = null;

    @Override
    protected CommonCommands getTransactionCommands() throws Throwable {
        if (transactionStoreCommands == null) {
            transactionStoreCommands = new TransactionStoreCommands(getMyLogger(),
                    "  ",
                    getOA2SE());
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
        }
        return oa2AdminClientCommands;
    }

    OA2PermissionCommands oa2PermissionCommands = null;

    public OA2PermissionCommands getPermissionCommands() throws Throwable {
        if (oa2PermissionCommands == null) {
            oa2PermissionCommands = new OA2PermissionCommands(getMyLogger(), "  ", getOA2SE().getPermissionStore());
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
        if (inputLine.hasArg(VIRTUAL_ORGANIZATION)) {
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
}
