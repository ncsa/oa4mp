package org.oa4mp.server.admin.myproxy.oauth2.tools;

import edu.uiuc.ncsa.security.core.exceptions.ConnectionException;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.util.cli.*;
import org.oa4mp.client.api.ClientXMLTags;
import org.oa4mp.delegation.common.OA4MPVersion;

import java.util.ArrayList;
import java.util.Arrays;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/11/16 at  2:51 PM
 */
public class OA2CommandLineClient extends ConfigurableCommandsImpl {
    @Override
    public String getComponentName() {
        return ClientXMLTags.COMPONENT;
    }


    @Override
    public void useHelp() {

    }

    @Override
    public String getPrompt() {
        return "clc>";
    }

    @Override
    public void bootstrap(InputLine inputLine) throws Throwable {
super.bootstrap(inputLine);
    }

    @Override
    public String getName() {
        return "oa4mp";
    }

    @Override
    public HelpUtil getHelpUtil() {
        return null;
    }

    public OA2CommandLineClient(MyLoggingFacade logger) {
        super(logger);
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
            OA2CommandLineClient clc = new OA2CommandLineClient(null);
            setInstance(clc);
            clc.runnit(args, clc );
/*
            CLIDriver cli = new CLIDriver(clc); // actually run the driver that parses commands and passes them along
            inputLine = cli.bootstrap(inputLine);
            clc.bootstrap(inputLine);
            OA2CLCCommands usc = new OA2CLCCommands(cli.getLogger(), clc);
            usc.setConfigFile(clc.getConfigFile());
            FormatUtil.setIoInterface(cli.getIOInterface());
            cli.addCommands(usc);
            usc.bootMessage();
            cli.start();
*/
     } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    /*

        if (inputLine.hasArg("-sas")) {
            setupSAS(inputLine);
            return;
        }
        OA2Commands oa2Commands = new OA2Commands(null);
        CLIDriver cli = new CLIDriver(oa2Commands); // actually run the driver that parses commands and passes them along
        inputLine = cli.bootstrap(inputLine);
        oa2Commands.startup(inputLine); // read the command line options and such to set the state
        cli.start();
     */
    /**
     * Does all the actual work of running this once it gets the right command line client
     * instance.
     * @param args
     * @param clc
     * @throws Throwable
     */
    protected  void runnit(String[] args, OA2CommandLineClient clc) throws Throwable {
        ArrayList<String> aaa = new ArrayList<>();
        aaa.add(OA2Commands.class.getSimpleName()); // dummy first argument
        aaa.addAll(Arrays.asList(args));
        InputLine inputLine = new InputLine(aaa);
        CLIDriver cli = new CLIDriver(clc);
        try {// actually run the driver that parses commands and passes them along
            clc.bootstrap(inputLine);
        }catch(ConnectionException ce){
            say("could not connect to server");
        }catch(Throwable e) {
            if(cli.isVerbose()){
                e.printStackTrace();
            }
            say("erro reading configuration file: " + e.getMessage());

        }
        OA2CLCCommands usc = new OA2CLCCommands(cli.getLogger(), clc);
        usc.setConfigFile(clc.getConfigFile());
        FormatUtil.setIoInterface(cli.getIOInterface());
        cli.addCommands(usc);
        usc.bootMessage();
        cli.start();

        /* Proposed NEW

            OA2CommandLineClient clc = new OA2CommandLineClient(null);
            CLIDriver cli = new CLIDriver(clc); // actually run the driver that parses commands and passes them along
            clc.bootstrap(inputLine);
            OA2CLCCommands usc = new OA2CLCCommands(cli.getLogger(), clc);
            usc.setConfigFile(clc.getConfigFile());
            FormatUtil.setIoInterface(cli.getIOInterface());
            cli.addCommands(usc);
            usc.bootMessage();
            cli.start();

         */
/* OLD
        CLIDriver cli = new CLIDriver();
        cli.bootstrap(inputLine);
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
*/

    }

    @Override
    public void print_help() throws Exception {
    }

    public void start(String[] args) throws Exception {
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
        String stars = StringUtils.repeatString("*", width + 1);
        say(stars);
        say(StringUtils.pad2("* OA4MP CLC (command line client)", width) + "*");
        say(StringUtils.pad2("* Version " + OA4MPVersion.VERSION_NUMBER, width) + "*");
        say(StringUtils.pad2("* By Jeff Gaynor  NCSA", width) + "*");
        say(StringUtils.pad2("*  (National Center for Supercomputing Applications)", width) + "*");
        say(StringUtils.pad2("*", width) + "*");
        say(StringUtils.pad2("* type 'help' for a list of commands", width) + "*");
        say(StringUtils.pad2("*      'exit' or 'quit' to end this session.", width) + "*");
        say(stars);
    }

    @Override
    public boolean use(InputLine inputLine) throws Exception {
        // No components so this is a stub.
        return false;
    }
}
