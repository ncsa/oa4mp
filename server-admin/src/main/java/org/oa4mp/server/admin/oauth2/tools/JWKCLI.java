package org.oa4mp.server.admin.oauth2.tools;

import edu.uiuc.ncsa.security.core.util.*;
import edu.uiuc.ncsa.security.util.cli.*;
import org.oa4mp.delegation.common.OA4MPVersion;

import java.util.logging.Level;

/**
 * Top-level class for the JWT and JWK command line utilities. This lets you create keys, create id tokens
 * sign them, verify them etc.
 * <p>Created by Jeff Gaynor<br>
 * on 5/6/19 at  2:37 PM
 */
public class JWKCLI extends ConfigurableCommandsImpl {

    public JWKCLI(MyLoggingFacade logger) {
        super(logger);
    }


    public void about() {
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
            // Do any help first
            if (inputLine.hasArg(SHORT_HELP_FLAG) || inputLine.hasArg(LONG_HELP_FLAG)) {
                JWKCLI jwkcli = new JWKCLI(null);
                jwkcli.useHelp();
                return;
            }

            JWKUtilCommands jwkUtilCommands = new JWKUtilCommands(null);

            CLIDriver cli = new CLIDriver(jwkUtilCommands); // actually run the driver that parses commands and passes them along
            inputLine = cli.bootstrap(inputLine);
            jwkUtilCommands.bootstrap(inputLine); // read the command line options and such to set the state
            if (args == null || args.length == 0) {
                JWKCLI jwkcli = new JWKCLI(null);
                jwkcli.useHelp();
            }
            cli.start();
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }
    public static void OLDmain(String[] args) throws Throwable{

        InputLine argLine = new InputLine(JWKCLI.class.getSimpleName(), args); // now we have a bunch of utilities for this

        // In order of importance for command line flags.


        boolean isVerbose = argLine.hasArg(SHORT_VERBOSE_FLAG) || argLine.hasArg(LONG_VERBOSE_FLAG);
        // again, a batch file means every line in the file is a separate comamand, aside from comments

        MyLoggingFacade myLoggingFacade = null;
        if (argLine.hasArg("-log")) {

            String logFileName = argLine.getNextArgFor("-log");
            LoggerProvider loggerProvider = new LoggerProvider(logFileName,
                    "JWKUtil logger", 1, 1000000, true,true, Level.INFO);
            myLoggingFacade = loggerProvider.get(); // if verbose
            argLine.removeSwitchAndValue("-log"); // This should never be passed as an argument!
        }

        JWKCLI jwkcli = new JWKCLI(myLoggingFacade);
            jwkcli.useHelp();
        JWKUtilCommands jwkUtilCommands = new JWKUtilCommands(myLoggingFacade);
        jwkUtilCommands.setVerbose(isVerbose);
        jwkUtilCommands.setPrintOuput(true);
        try {
            CLIDriver cli = new CLIDriver(jwkUtilCommands);
            // Easy case -- no arguments, so just start.
            if (args == null || args.length == 0) {
                jwkcli.about();
                cli.start();
                return;
            }
            // alternately, parse the arguments
            // check for help first
            if (argLine.hasArg(SHORT_HELP_FLAG) || argLine.hasArg(LONG_HELP_FLAG)) {
                jwkcli.useHelp();
                return;
            }

            String cmdLine = args[0];
            for (int i = 1; i < args.length; i++) {
                    cmdLine = cmdLine + " " + args[i];
            }
            cli.execute(cmdLine);

        } catch (Throwable t) {
            System.exit(1);
            t.printStackTrace();
        }
    }

    protected JWKUtilCommands getJWKCommands(CLIDriver cli) {
        for (Commands c : cli.getCLICommands()) {
            if (c instanceof JWKUtilCommands) {
                return (JWKUtilCommands) c;
            }
        }

        return null;
    }

    /**
     * Reads command line for batch flag or batch file, sets the flag for batch processing, then invokes the
     * main event loop.
     * @param cli
     * @param arg
     * @throws Exception
     */
/*    protected void processBatchModeCommand(CLIDriver cli, InputLine arg) throws Exception {
        JWKUtilCommands jwkCommands = getJWKCommands(cli);
        if (jwkCommands == null) {
            throw new NFWException("Error: No JWKUtilCommands configured, hence no logging.");
        }
        jwkCommands.setBatchMode(true);
        // need to tease out the intended line to execute. The arg line looks like
        // jwkutil -batch A B C
        // so we need to drop the name of the function and the -batch flag.
        arg.removeSwitch(BATCH_MODE_FLAG);
        arg.removeSwitch(BATCH_FILE_MODE_FLAG);
        arg.removeSwitch(DUMMY_FUNCTION);
        cli.execute(arg);
    }*/

/*
    protected void batchFileHelp() {
        say("Running batch files.");
        say("You can run scripts from the command line by passing in a file,");
        say("any line that starts with a # is a comment.");
        say("All lines MUST end with a ; (which is discarded at processing).");
        say("You may have commands across multiple lines with all the whitespace you want, but");
        say("at processing each line will be concatenated with a space, so don't break tokens over ");
        say("lines. See the readme.txt for more and look at any .cmd file in this distro for examples.");
    }
*/

    /**
     * Parses the file for commands and runs them.
     * @throws Throwable
     */
/*
    protected void processBatchFile(String fileName, CLIDriver cli) throws Throwable {
        if (fileName.toLowerCase().equals("--help")) {
            batchFileHelp();
            return;
        }
        if (fileName == null || fileName.isEmpty()) {
            throw new FileNotFoundException("Error: The file name is missing.");
        }
        File file = new File(fileName);
        if (!file.exists()) {
            throw new FileNotFoundException("Error: The file \"" + fileName + "\" does not exist");
        }
        if (!file.isFile()) {
            throw new FileNotFoundException("Error: The object \"" + fileName + "\" is not a file.");
        }
        if (!file.canRead()) {
            throw new GeneralException("Error: Cannot read file \"" + fileName + "\". Please check your permissions.");
        }
        FileReader fis = new FileReader(file);
        DDParser ddp = new DDParser();
        List<String> commands = ddp.parse(fis);
        //List<String> commands = ParserUtil.processInput(fis);
        JWKUtilCommands jwkCommands = getJWKCommands(cli);
        if (jwkCommands == null) {
            throw new NFWException("Error: No JWKUtilCommands configured, hence no logging.");
        }
        jwkCommands.setBatchMode(true);

        for (String command : commands) {
            try {
                if (cli.hasEnv()) {
                    command = TemplateUtil.replaceAll(command, cli.getEnv());
                }
                int rc = cli.execute(command);
                switch (rc) {
                    // Hint: The colons in the messages line up (more or less) so that the log file is very easily readable at a glance.
                    case CLIDriver.ABNORMAL_RC:
                        jwkCommands.error("Error: \"" + command + "\"");
                        break;
                    case CLIDriver.HELP_RC:
                        jwkCommands.info("  Help: invoked.");
                        break;
                    case CLIDriver.OK_RC:
                    default:
                        if (jwkCommands.isVerbose()) {
                            jwkCommands.info("    ok: \"" + command + "\"");
                        }
                }

            } catch (Throwable t) {
                jwkCommands.error(t, "Error executing batch file command \"" + command + "\"");
            }

        }

    }
*/

    protected void start(String[] args) throws Exception {
        about();
/*        if (!getOptions(args)) {
            say("Warning: no configuration file specified. type in 'load --help' to see how to load one.");
            return;
        }*/
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

