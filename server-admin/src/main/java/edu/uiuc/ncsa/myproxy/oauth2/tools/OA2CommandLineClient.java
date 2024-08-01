package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oauth2.base.CommandLineClient;
import edu.uiuc.ncsa.oa4mp.OA4MPVersion;
import edu.uiuc.ncsa.security.core.exceptions.ConnectionException;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;
import edu.uiuc.ncsa.security.util.cli.FormatUtil;
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

    public void setLoader(ConfigurationLoader<? extends AbstractEnvironment> loader) {
        this.loader = loader;
    }

    ConfigurationLoader<? extends AbstractEnvironment> loader;

    @Override
    public ConfigurationLoader<? extends AbstractEnvironment> getLoader() {
        //return new OA2ClientLoader<>(getConfigurationNode(), getMyLogger());
        return loader;
    }

    public static OA2CommandLineClient getInstance() {
        if (instance == null) {
            instance = new OA2CommandLineClient(null);
        }
        return instance;
    }

    public static void setInstance(OA2CommandLineClient instance) {
        OA2CommandLineClient.instance = instance;
    }

    static OA2CommandLineClient instance = null;

    public static void main(String[] args) {
        try {
            OA2CommandLineClient oa2CommandLineClient = new OA2CommandLineClient(null);
      //      oa2CommandLineClient.start(args);
            oa2CommandLineClient.runnit(args, getInstance());
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    /**
     * Does all the actual work of running this once it gets the right command line client
     * instance.
     * @param args
     * @param clc
     * @throws Throwable
     */
    protected  void runnit(String[] args, OA2CommandLineClient clc) throws Throwable {
        clc.start(args);
        OA2CLCCommands usc = new OA2CLCCommands(clc.getMyLogger(), clc);
        usc.setConfigFile(clc.getConfigFile());
        FormatUtil.setIoInterface(clc.getIOInterface());
        CLIDriver cli = new CLIDriver(clc.getIOInterface());
        cli.addCommands(usc);
        cli.setLineCommentStart(COMMENT_START);
        cli.setIOInterface(clc.getIOInterface());
        usc.bootMessage();
        cli.start();

    }

    @Override
    public void print_help() throws Exception {
    }

    public void start(String[] args) throws Exception {
        if (!getOptions(args)) {
            say("Warning: no configuration file specified. type in 'load --help' to see how to load one.");
            return;
        }
        try {
            initialize();
            about();
        } catch (Throwable mc) {

            Throwable t = mc;
            if(mc.getCause()!=null){
                t = mc.getCause();
            }
            if(!(mc instanceof ConnectionException)) {
                // Don't print error message here, let it propagate back.
                say("Could not load the configuration:\"" + t.getMessage() + "\"");
            }
        }
    }

    @Override
    protected ConfigurationLoader<? extends AbstractEnvironment> figureOutLoader(String fileName, String configName) throws Throwable {
        ConfigLoaderTool configLoaderTool = new ConfigLoaderTool();
        return configLoaderTool.figureOutClientLoader(fileName, configName, getComponentName());
    }
     protected void banner(){
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
        /*



  ,ad8888ba,    88888888ba,    88                ,ad8888ba,   88           ,ad8888ba,
 d8"'    `"8b   88      `"8b   88               d8"'    `"8b  88          d8"'    `"8b
d8'        `8b  88        `8b  88              d8'            88         d8'
88          88  88         88  88              88             88         88
88          88  88         88  88              88             88         88
Y8,    "88,,8P  88         8P  88              Y8,            88         Y8,
 Y8a.    Y88P   88      .a8P   88               Y8a.    .a8P  88          Y8a.    .a8P
  `"Y8888Y"Y8a  88888888Y"'    88888888888       `"Y8888Y"'   88888888888  `"Y8888Y"'




         */
     }
    public void about() {
        int width = 60;
        banner();
        String stars = StringUtils.rightPad("", width + 1, "*");
        say(stars);
        say(padLineWithBlanks("* OA4MP CLC (command line client)", width) + "*");
        say(padLineWithBlanks("* Version " + OA4MPVersion.VERSION_NUMBER, width) + "*");
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
        return false;
    }
}
