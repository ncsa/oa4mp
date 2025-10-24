package org.oa4mp.server.admin.oauth2.tools;

import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;
import edu.uiuc.ncsa.security.util.cli.ConfigurableCommandsImpl2;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import org.oa4mp.delegation.common.OA4MPVersion;

/**
 * Top-level class for the JWT and JWK command line utilities. This lets you create keys, create id tokens
 * sign them, verify them etc.
 * <p>Created by Jeff Gaynor<br>
 * on 5/6/19 at  2:37 PM
 */
public class JWKCLI extends ConfigurableCommandsImpl2 {

    public JWKCLI(CLIDriver driver) {
        super(driver);
    }

    @Override
    public void about(boolean showBanner, boolean showHeader) {
    int width = 60;
        String stars = StringUtils.repeatString("*", width + 1);
        say(stars);
        say(StringUtils.pad2("* JSON Web Token CLI (Command Line Interpreter)", width) + "*");
        say(StringUtils.pad2("* Version " + OA4MPVersion.VERSION_NUMBER, width) + "*");
        say(StringUtils.pad2("* By Jeff Gaynor  NCSA", width) + "*");
        say(StringUtils.pad2("*  (National Center for Supercomputing Applications)", width) + "*");
        say(StringUtils.pad2("*", width) + "*");
        say(StringUtils.pad2("* type 'help' for a list of commands", width) + "*");
        say(StringUtils.pad2("*      'exit' or 'quit' to end this session.", width) + "*");
        say(stars);
    }

    ConfigurationLoader<? extends AbstractEnvironment> loader = null;
    @Override
    public ConfigurationLoader<? extends AbstractEnvironment> getLoader() {
        return loader;
    }

    @Override
    public String getName() {
        return "jwt";
    }

    @Override
    public String getPrompt() {
        return getName()+">";
    }

    @Override
    public String getComponentName() {
        return null;
    }

    @Override
    public void useHelp() {
        say("You may use this in both interactive mode and as a command line utility.");
        say("Here is a list of commands: An asterisk (X) means it is for interactive mode only");
        say("Key commands");
        say("------------");
        say("create_keys");
        say("create_public_keys");
        say("*set_keys");
        say("list_keys");
        say("list_key_ids");
        say("*set_default_id");
        say("*print_default_id");
        say("*print_well_known");
        say("Claim Commands");
        say("--------------");
        say("create_claims");
        say("parse_claims");
        say("Token Commands");
        say("--------------");
        say("create_token");
        say("generate_token");
        say("print_token");
        say("validate_token");
        say("Other commands");
        say("--------------");
        say("base64");
        say("set_no_output");
        say("set_verbose");
        say("To get a full explanation of the command and its syntax, type \"command --help \".");
        say("Command line options");
        say("--------------------");
        say("These are flags and arguments to the command line processor.");
        say(SHORT_VERBOSE_FLAG + "," + LONG_VERBOSE_FLAG + "= turn verbose mode on. This allows you to see the internal workings of processing");
        say("   You can set this in a batch file by invoking set_verbose true|false");
        say(SHORT_NO_OUTPUT_FLAG + ", " + LONG_NO_OUTPUT_FLAG + " = turn off all output");
        say("   You can set this in a batch file by invoking set_no_ouput true|false");
    }



    public static String SHORT_HELP_FLAG = "-help";
    public static String LONG_HELP_FLAG = "--help";
    public static String SHORT_VERBOSE_FLAG = "-v";
    public static String LONG_VERBOSE_FLAG = "--verbose";
    public static String SHORT_NO_OUTPUT_FLAG = "-noOuput";
    public static String LONG_NO_OUTPUT_FLAG = "--noOuput";


    public static void main(String[] args) throws Throwable{
        try {
            InputLine inputLine = new InputLine(JWKCLI.class.getSimpleName(), args); // now we have a bunch of utilities for this
            JWKUtilCommands jwkUtilCommands = new JWKUtilCommands(null);

            CLIDriver cli = new CLIDriver(jwkUtilCommands); // actually run the driver that parses commands and passes them along
            jwkUtilCommands.setDriver(cli);
            inputLine = cli.bootstrap(inputLine);
            jwkUtilCommands.bootstrap(inputLine); // read the command line options and such to set the state
            if (inputLine.hasArg(SHORT_HELP_FLAG,LONG_HELP_FLAG)) {
                JWKCLI jwkcli = new JWKCLI(cli);
                jwkcli.useHelp();
                return;
            }
            cli.start();
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }

    /**
     * Dummy method that looks like any other command but just prints help for the entire app.
     * @param inputLine
     */
     public void useHelp(InputLine inputLine) {
        useHelp();
        return;
     }
    @Override
    public void setLoader(ConfigurationLoader<? extends AbstractEnvironment> loader) {
    this.loader = getLoader();
    }

    @Override
    protected ConfigurationLoader<? extends AbstractEnvironment> figureOutLoader(String fileName, String configName) throws Throwable {
        ConfigLoaderTool configLoaderTool = new ConfigLoaderTool();
        return configLoaderTool.figureOutClientLoader(fileName, configName, getComponentName());
    }
}

