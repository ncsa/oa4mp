package org.oa4mp.server.admin.myproxy.oauth2.base;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.cli.*;
import org.oa4mp.server.api.OA4MPConfigTags;
import org.oa4mp.server.api.ServiceEnvironment;

import java.io.OutputStream;
import java.io.PrintStream;
import java.util.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/27/15 at  1:49 PM
 */
public abstract class BaseCommands extends ConfigurableCommandsImpl implements ComponentManager {

    public static final String CLIENTS = "clients";
    public static final String CLIENT_APPROVALS = "approvals";
    public static final String COPY = "copy";
    public String TRANSACTION_COMMAND = "transactions";
    protected Map<String, CLIDriver> drivers = new HashMap<>();

    protected List<String> components = new ArrayList<>();

    protected boolean showHeader = true;
    protected boolean showLogo = true;

    protected void init()  {
        try {
            if (drivers.isEmpty()) {
                drivers.put(CLIENTS, createCLIDriver(getClientCommands()));
                drivers.put(CLIENT_APPROVALS, createCLIDriver(getClientApprovalCommands()));
                drivers.put(TRANSACTION_COMMAND, createCLIDriver(getTransactionCommands()));
            }
        }catch(Throwable t) {
            if( t instanceof RuntimeException ){
                throw (RuntimeException)t;
            }
            throw new  GeneralException("Unable to initialize CLI components", t);
        }
    }

    @Override
/*    public List<String> listComponents() {
        return components;
    }*/
    public Set<String> listComponents() {
        return drivers.keySet();
    }

    public abstract void about();

    public abstract ClientStoreCommands getClientCommands() throws Throwable;

    public abstract CopyCommands getCopyCommands() throws Throwable;

    protected abstract CommonCommands getTransactionCommands() throws Throwable;


    protected BaseCommands(MyLoggingFacade logger) {
        super(logger);
     //   init();
    }

    @Override
    public String getComponentName() {
        return OA4MPConfigTags.COMPONENT;
    }

    protected String logoName = "times";

    /**
     * command line arguments are <br>
     * <ul>
     *     <li>-noLogo - do not show logo</li>
     *     <li>-noHeader - do not show splash screen with author, version </li>
     *     <li>-v = do not suppress startup messages. A lot of 3rd party software spits stuff out
     *     and it is normally hidden. This prints it all out.</li>
     *     <li>-silent = same as -noLogo and -noHeader</li>
     *     <li>-logo name = use the named logo. Standard are Times, Roman (like Times but bigger),
     *     OS2 - groovy font, Fraktur - Old German Font or Plain = barebones sans-serif,
     *     None = none (same as -noLogo).
     *     Times is the default.</li>
     * </ul>
     *
     * @param args
     * @throws Exception
     */
    protected void startup(String[] args) throws Exception {
        InputLine inputLine = new InputLine(args);
        showLogo = !inputLine.hasArg("-noLogo");
        showHeader = !inputLine.hasArg("-noHeader");
        if (inputLine.hasArg("-silent")) {
            showHeader = false;
            showLogo = false;
        }
        boolean printStartup = inputLine.hasArg("-v");
        if (inputLine.hasArg("-logo")) {
            logoName = inputLine.getNextArgFor("-logo").toLowerCase();
        }

        about();
        if (!getOptions(args)) {
            say("Warning: no configuration file specified. type in 'load --help' to see how to load one.");
            return;
        }
        if (printStartup) {
            initialize(); // No logging so a there might be a bunch of stuff that gets spit out.
            return;
        }
        // pipe startup messages to dev null:
        if(getIOInterface() instanceof BasicIO) {
            PrintStream out = System.out;
            PrintStream err = System.err;
            System.setOut(new PrintStream(OutputStream.nullOutputStream()));
            System.setErr(new PrintStream(OutputStream.nullOutputStream()));
            initialize();
            System.setOut(out);
            System.setErr(err);
        }
        init();
    }


    public ServiceEnvironment getServiceEnvironment() throws Exception {
        return (ServiceEnvironment) getEnvironment();
    }


    public ClientApprovalStoreCommands getClientApprovalCommands() throws Throwable {
        return new ClientApprovalStoreCommands(getMyLogger(), "  ", getServiceEnvironment().getClientApprovalStore());
    }

    @Override
    public boolean use(InputLine inputLine) throws Throwable {
        CommonCommands commands = null;

        if (inputLine.hasArg(CLIENTS)) {
            commands = getClientCommands();
        }
        if (inputLine.hasArg(CLIENT_APPROVALS)) {
            commands = getClientApprovalCommands();
        }
/*        if (inputLine.hasArg(COPY)) {
            commands = getNewCopyCommands();
        }
        if (inputLine.hasArg(PARSER_COMMAND)) {
            commands = getNewParserCommands();
        }*/
        if (inputLine.hasArg(TRANSACTION_COMMAND)) {
            commands = getTransactionCommands();
        }
        if (commands != null) {
            return switchOrRun(inputLine, commands);
        }

        if (super.use(inputLine)) {
            return true;
        }

        return false;
    }

    /**
     * Either switch to another component or (if there are arguments) simply run the
     * single command and return. Note that each component has stored state, so
     * these will be run with whatever is in that state.
     *
     * @param inputLine
     * @param commands
     * @return
     */
    protected boolean switchOrRun(InputLine inputLine, CommonCommands commands) {
        boolean switchComponent = 1 < inputLine.getArgCount();

        CLIDriver cli = new CLIDriver();
        cli.setIOInterface(commands.getIOInterface());
        cli.addCommands(commands);
        cli.setEnv(getGlobalEnv());
        cli.setComponentManager(this);
        if (switchComponent) {
            inputLine.removeArgAt(0); // removes original arg ("use")
            cli.execute(inputLine.removeArgAt(0)); // removes components before executing
        } else {
            cli.start();
        }
        return true;
    }
protected CLIDriver createCLIDriver(CommonCommands commands){
    CLIDriver cli = new CLIDriver();
    cli.setIOInterface(commands.getIOInterface());
    cli.addCommands(commands);
    cli.setEnv(getGlobalEnv());
    cli.setComponentManager(this);
    return cli;
}

    protected boolean hasComponent(String componentName) {
        return componentName.equals(CLIENTS) ||
                componentName.equals(CLIENT_APPROVALS) ||
                componentName.equals(COPY) ;
    }

    protected void runComponent(String componentName) throws Throwable {
        CommonCommands commonCommands = null;
    /*    if (componentName.equals(PARSER_COMMAND)) {
            commonCommands = getNewParserCommands();
        }*/
        if (componentName.equals(CLIENTS)) {
            commonCommands = getClientCommands();
        }
        if (componentName.equals(CLIENT_APPROVALS)) {
            commonCommands = getClientApprovalCommands();
        }
        if (componentName.equals(COPY)) {
            commonCommands = getCopyCommands();
        }
        if (commonCommands != null) {
            CLIDriver cli = new CLIDriver(commonCommands);
            cli.start();

        }
    }

//    public abstract ParserCommands getNewParserCommands() throws Throwable;

    protected boolean executeComponent() throws Throwable {
        if (hasOption(USE_COMPONENT_OPTION, USE_COMPONENT_LONG_OPTION)) {
            String component = getCommandLine().getOptionValue(USE_COMPONENT_OPTION);
            if (component != null && 0 < component.length()) {
                if (!hasComponent(component)) {
                    say("Unknown component name of \"" + component + "\". ");
                    return false;
                }
                runComponent(component);
                return true;
            } else {
                say("Caution, you specified using a component, but did not specify what the component is.");
            }
        }
        return false;
    }

    public void useHelp() {
        say("Choose the component you wish to use.");
        say("you specify the component as use + name. Supported components are");
        say(CLIENTS + " - edit client records");
        say(CLIENT_APPROVALS + " - edit client approval records\n");
        say(COPY + " - copy an entire store.\n");
        say("e.g.\n\nuse " + CLIENTS + "\n\nwill call up the client management component.");
        say("Type 'exit' or /q when you wish to exit the component and return to the main menu");
    }

}
