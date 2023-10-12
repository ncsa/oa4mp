package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oauth2.base.CommandLineClient;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientLoader;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.core.util.LoggingConfigLoader;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;
import edu.uiuc.ncsa.security.util.cli.HelpUtil;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import org.apache.commons.lang.StringUtils;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/11/16 at  2:51 PM
 */
public class OA2CommandLineClient extends CommandLineClient {
    @Override
    public void bootstrap() throws Throwable {

    }

    @Override
    public HelpUtil getHelpUtil() {
        return null;
    }

    public OA2CommandLineClient(MyLoggingFacade logger) {
        super(logger);
    }

    @Override
    public List<String> listComponents() {
        return null;
    }

    @Override
    public ConfigurationLoader<? extends AbstractEnvironment> getLoader() {
        return new OA2ClientLoader<>(getConfigurationNode(), getMyLogger());
    }

    public static void main(String[] args) {
        try {
            OA2CommandLineClient testCommands = new OA2CommandLineClient(null);
            testCommands.start(args);
            OA2CLCCommands usc = new OA2CLCCommands(testCommands.getMyLogger(), testCommands);
            usc.setConfigFile(testCommands.getConfigFile());
            CLIDriver cli = new CLIDriver(usc);
            usc.bootMessage();
            cli.start();
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    @Override
    public void print_help() throws Exception{
    }

    public void start(String[] args) throws Exception {
        if (!getOptions(args)) {
            say("Warning: no configuration file specified. type in 'load --help' to see how to load one.");
            return;
        }
        about();
        try {
            initialize();
        }catch(MyConfigurationException mc){
            say("Could not load the configuration:\""+ mc.getMessage() + "\"");
        }

    }

    public void about() {
        int width = 60;
        say("                                                              \n" +
                "  .g8\"\"8q.      db                 `7MMM.     ,MMF'`7MM\"\"\"Mq. \n" +
                ".dP'    `YM.   ;MM:                  MMMb    dPMM    MM   `MM.\n" +
                "dM'      `MM  ,V^MM.         ,AM     M YM   ,M MM    MM   ,M9 \n" +
                "MM        MM ,M  `MM        AVMM     M  Mb  M' MM    MMmmdM9  \n" +
                "MM.      ,MP AbmmmqMA     ,W' MM     M  YM.P'  MM    MM       \n" +
                "`Mb.    ,dP'A'     VML  ,W'   MM     M  `YM'   MM    MM       \n" +
                "  `\"bmmd\"'.AMA.   .AMMA.AmmmmmMMmm .JML. `'  .JMML..JMML.     \n" +
                "                              MM                              \n" +
                "                              MM                             ");
        String stars = StringUtils.rightPad("", width + 1, "*");
        say(stars);
        say(padLineWithBlanks("* OA4MP CLC (command line client)", width) + "*");
        say(padLineWithBlanks("* Version " + LoggingConfigLoader.VERSION_NUMBER, width) + "*");
        say(padLineWithBlanks("* By Jeff Gaynor  NCSA", width) + "*");
        say(padLineWithBlanks("*  (National Center for Supercomputing Applications)", width) + "*");
        say(padLineWithBlanks("*", width) + "*");
        say(padLineWithBlanks("* type 'help' for a list of commands", width) + "*");
        say(padLineWithBlanks("*      'exit' or 'quit' to end this session.", width) + "*");
        say(stars);
    }

    @Override
    public boolean use(InputLine inputLine) throws Exception {
        // No components so this is a stub.
/*        String indent = "  ";
        if (inputLine.hasArg("test")) {
            OA2CLCCommands usc = new OA2CLCCommands(getMyLogger(), (ClientEnvironment) getEnvironment());
            CLIDriver cli = new CLIDriver(usc);
            cli.start();
            return true;
        }*/
        return false;
    }
}
