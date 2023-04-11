package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.util.*;
import edu.uiuc.ncsa.security.util.cli.*;
import edu.uiuc.ncsa.security.util.configuration.TemplateUtil;
import edu.uiuc.ncsa.security.util.functor.parser.event.ParserUtil;
import org.apache.commons.lang.StringUtils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.List;
import java.util.Vector;

import static edu.uiuc.ncsa.security.util.cli.CommonCommands.BATCH_FILE_MODE_FLAG;
import static edu.uiuc.ncsa.security.util.cli.CommonCommands.BATCH_MODE_FLAG;

/**
 * Top-level class for the JWT and JWK command line utilities. This lets you create keys, create id tokens
 * sign them, verify them etc.
 * <p>Created by Jeff Gaynor<br>
 * on 5/6/19 at  2:37 PM
 */
public class JWKCLI extends ConfigurableCommandsImpl {

    @Override
    public void bootstrap() throws Throwable {

    }

    @Override
    public HelpUtil getHelpUtil() {
        return null;
    }

    public JWKCLI(MyLoggingFacade logger) {
        super(logger);
    }

    @Override
    public List<String> listComponents() {
        return null;
    }

    public void about() {
        int width = 60;
        String stars = StringUtils.rightPad("", width + 1, "*");
        say(stars);
        say(padLineWithBlanks("* JSON Web Token CLI (Command Line Interpreter)", width) + "*");
        say(padLineWithBlanks("* Version " + LoggingConfigLoader.VERSION_NUMBER, width) + "*");
        say(padLineWithBlanks("* By Jeff Gaynor  NCSA", width) + "*");
        say(padLineWithBlanks("*  (National Center for Supercomputing Applications)", width) + "*");
        say(padLineWithBlanks("*", width) + "*");
        say(padLineWithBlanks("* type 'help' for a list of commands", width) + "*");
        say(padLineWithBlanks("*      'exit' or 'quit' to end this session.", width) + "*");
        say(stars);
    }

    @Override
    public void print_help(InputLine inputLine) throws Exception{
    say("Need to write help.");
    }

    @Override
    public ConfigurationLoader<? extends AbstractEnvironment> getLoader() {
        return null;
    }

    @Override
    public String getPrompt() {
        return "jwt>";
    }

    @Override
    public String getComponentName() {
        return null;
    }

    @Override
    public void useHelp() {
        say("You may use this in both interactive mode and as a command line utility.");
        say("To use in batch mode, supply the " + BATCH_MODE_FLAG + " flag.");
        say("This will suppress all output and will not prompt for missing arguments to functions.");
        say("If you omit this flag, then missing arguments will still cause you to be prompted.");
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
        say(BATCH_MODE_FLAG + "= interpret everything else on the command line as a command, aside from flags. Note this means you can execute a single command.");
        say(BATCH_FILE_MODE_FLAG + "= this is the fully qualified path to a file of commands which will be interpreted one after the other.");
    }


    protected static String DUMMY_FUNCTION = "dummy0"; // used to create initial command line

    public static String SHORT_HELP_FLAG = "-help";
    public static String LONG_HELP_FLAG = "--help";
    public static String SHORT_VERBOSE_FLAG = "-v";
    public static String LONG_VERBOSE_FLAG = "--verbose";
    public static String SHORT_NO_OUTPUT_FLAG = "-noOuput";
    public static String LONG_NO_OUTPUT_FLAG = "--noOuput";


    public static void main(String[] args) throws Throwable{
        Vector<String> vector = new Vector<>();
        vector.add(DUMMY_FUNCTION); // Dummy zero-th arg.
        for (String arg : args) {
            vector.add(arg);
        }
        InputLine argLine = new InputLine(vector); // now we have a bunch of utilities for this

        // In order of importance for command line flags.


        boolean isVerbose = argLine.hasArg(SHORT_VERBOSE_FLAG) || argLine.hasArg(LONG_VERBOSE_FLAG);
        // again, a batch file means every line in the file is a separate comamand, aside from comments
        boolean hasBatchFile = argLine.hasArg(BATCH_FILE_MODE_FLAG);
        // Batch mode means that the command line is interpreted as a single command. This executes one command, batch mode does many.
        boolean isBatchMode = argLine.hasArg(JWKUtilCommands.BATCH_MODE_FLAG);
        boolean isNoOuput = (argLine.hasArg(SHORT_NO_OUTPUT_FLAG) || argLine.hasArg(LONG_NO_OUTPUT_FLAG));

        MyLoggingFacade myLoggingFacade = null;
        if (argLine.hasArg("-log")) {

            String logFileName = argLine.getNextArgFor("-log");
            LoggerProvider loggerProvider = new LoggerProvider(logFileName,
                    "JWKUtil logger", 1, 1000000, false, isVerbose, false);
            myLoggingFacade = loggerProvider.get(); // if verbose
            argLine.removeSwitchAndValue("-log"); // This should never be passed as an argument!
        }

        JWKCLI jwkcli = new JWKCLI(myLoggingFacade);
        if (!(isBatchMode || hasBatchFile)) {
            // if not batch mode, print startup banner && help.
            jwkcli.useHelp();
        }
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
            jwkUtilCommands.setBatchMode(false);
            if (hasBatchFile) {
                jwkcli.processBatchFile(argLine.getNextArgFor(BATCH_FILE_MODE_FLAG), cli);
                return;
            }
            if (isBatchMode) {
                jwkcli.processBatchModeCommand(cli, argLine);
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
                if (args[i].equals(BATCH_MODE_FLAG)) {
                    jwkUtilCommands.setBatchMode(true);
                } else {
                    // don't keep the batch flag in the final arguments.
                    cmdLine = cmdLine + " " + args[i];
                }
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

    protected void processBatchModeCommand(CLIDriver cli, InputLine arg) throws Exception {
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
    }

    protected void batchFileHelp() {
        say("Running batch files.");
        say("You can run scripts from the command line by passing in a file,");
        say("any line that starts with a # is a comment.");
        say("All lines MUST end with a ; (which is discarded at processing).");
        say("You may have commands across multiple lines with all the whitespace you want, but");
        say("at processing each line will be concatenated with a space, so don't break tokens over ");
        say("lines. See the readme.txt for more and look at any .cmd file in this distro for examples.");
        say("And do remember that environment variables are not available inside these scripts.");
    }

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
        List<String> commands = ParserUtil.processInput(fis);
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

    protected void start(String[] args) throws Exception {
        about();
        if (!getOptions(args)) {
            say("Warning: no configuration file specified. type in 'load --help' to see how to load one.");
            return;
        }
    }


}

