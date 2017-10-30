package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.core.util.LoggingConfigLoader;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;
import edu.uiuc.ncsa.security.util.cli.CommonCommands;
import edu.uiuc.ncsa.security.util.cli.ConfigurableCommandsImpl;
import org.apache.commons.lang.StringUtils;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/5/17 at  3:31 PM
 */
public class SciTokensCLI extends ConfigurableCommandsImpl {
    public SciTokensCLI(MyLoggingFacade logger) {
        super(logger);
    }

    public void about() {
        int width = 60;
        String stars = StringUtils.rightPad("", width + 1, "*");
        say(stars);
        say(padLineWithBlanks("* SciTokens CLI (Command Line Interpreter)", width) + "*");
        say(padLineWithBlanks("* Version " + LoggingConfigLoader.VERSION_NUMBER, width) + "*");
        say(padLineWithBlanks("* By Jeff Gaynor  NCSA", width) + "*");
        say(padLineWithBlanks("*  (National Center for Supercomputing Applications)", width) + "*");
        say(padLineWithBlanks("*", width) + "*");
        say(padLineWithBlanks("* type 'help' for a list of commands", width) + "*");
        say(padLineWithBlanks("*      'exit' or 'quit' to end this session.", width) + "*");
        say(stars);
    }


    @Override
    public ConfigurationLoader<? extends AbstractEnvironment> getLoader() {
        return null;
    }

    @Override
    public String getPrompt() {
        return "sciTokens>";
    }

    @Override
    public String getComponentName() {
        return null;
    }

    @Override
    public void useHelp() {
        say("You may use this in both interactive mode and as a command line utility.");
        say("To use in batch mode, supply the " + CommonCommands.BATCH_MODE_FLAG + " flag.");
        say("This will suppress all output and will not prompt for missing arguments to functions.");
        say("If you omit this flag, then missing arguments will still cause you to be prompted.");
        say("Here is a list of commands:");
        say("create_claims");
        say("create_token");
        say("list_key_ids");
        say("list_keys");
        say("parse_claims");
        say("print_token");
        say("To get a full explination of the command and its syntax, type \"command --help \", e.g. ");
        say("java -jar scitokens.jar -batch create_keys -- help");
        say("  create_keys filename: This will create a JWK file and the corresponding public and private key files in pem format.");
        say("                        when this is done, the following files will be create filename.jwk, filename-public.pem and" +
                "                        filename-private.pem. At this point only 512 bit signing is supported.");
        say("                        NOTE: the pem files are supplied so you can use them with other applications. This only uses the .jwk file");
        say("  set_key filename: This will set the signing and validation key from the given file");
        say("  sign string: This creates an id token from the given string.");
        say("  -");
        say("Type 'exit' when you wish to exit the component and return to the main menu");
    }

    public static void main(String[] args) {
        SciTokensCLI oa2Commands = new SciTokensCLI(null);
        SciTokensCommands sciTokensCommands = new SciTokensCommands(null);
        try {
            CLIDriver cli = new CLIDriver(sciTokensCommands);
            if (args == null || args.length == 0) {
                //oa2Commands.start(args);
                cli.start();
                return;
            }
            sciTokensCommands.setBatchMode(false);
            // alternately, parse the arguments
            if (args[0].equalsIgnoreCase("--help")) {
                oa2Commands.useHelp();
                return;
            }
            String cmdLine = args[0];
            for (int i = 1; i < args.length; i++) {
                if (args[i].equals(CommonCommands.BATCH_MODE_FLAG)) {
                    sciTokensCommands.setBatchMode(true);
                } else {
                    // don't keep the batch flag in the final arguments.
                    cmdLine = cmdLine + " " + args[i];
                }
            }
            cli.execute(cmdLine);

        } catch (Throwable t) {
            if(sciTokensCommands.isBatchMode()){
                System.exit(1);
            }
            t.printStackTrace();
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
