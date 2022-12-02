package edu.uiuc.ncsa.myproxy.oauth2.base;

import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceEnvironment;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.cli.*;

import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/27/15 at  1:49 PM
 */
public abstract class BaseCommands extends ConfigurableCommandsImpl implements ComponentManager {

    public static final String CLIENTS = "clients";
    public static final String CLIENT_APPROVALS = "approvals";
    public static final String COPY = "copy";
    public String PARSER_COMMAND = "parser";
    public String TRANSACTION_COMMAND = "transactions";

 protected   List<String> components = new ArrayList<>();
    protected void init(){
        if(components.isEmpty()){
             components.add(CLIENTS);
             components.add(CLIENT_APPROVALS);
             components.add(COPY);
             components.add(PARSER_COMMAND);
             components.add(TRANSACTION_COMMAND);
        }
    }
    @Override
    public List<String> listComponents() {
        return components;
    }

    public abstract void about();

    public abstract ClientStoreCommands getNewClientStoreCommands() throws Throwable;

    public abstract CopyCommands getNewCopyCommands() throws Throwable;

    protected abstract CommonCommands getTransactionCommands() throws Throwable;


    protected BaseCommands(MyLoggingFacade logger) {
        super(logger);
        init();
    }

    @Override
    public String getComponentName() {
        return OA4MPConfigTags.COMPONENT;
    }


    protected void start(String[] args) throws Exception {
        about();
        if (!getOptions(args)) {
            say("Warning: no configuration file specified. type in 'load --help' to see how to load one.");
            return;
        }
        initialize();
    }


    public ServiceEnvironment getServiceEnvironment() throws Exception {
        return (ServiceEnvironment) getEnvironment();
    }


    public ClientApprovalStoreCommands getNewClientApprovalStoreCommands() throws Throwable {
        return new ClientApprovalStoreCommands(getMyLogger(), "  ", getServiceEnvironment().getClientApprovalStore());
    }

    @Override
    public boolean use(InputLine inputLine) throws Throwable {
        CommonCommands commands = null;

        if (inputLine.hasArg(CLIENTS)) {
            commands = getNewClientStoreCommands();
        }
        if (inputLine.hasArg(CLIENT_APPROVALS)) {
            commands = getNewClientApprovalStoreCommands();
        }
/*        if (inputLine.hasArg(COPY)) {
            commands = getNewCopyCommands();
        }
        if (inputLine.hasArg(PARSER_COMMAND)) {
            commands = getNewParserCommands();
        }*/
        if(inputLine.hasArg(TRANSACTION_COMMAND)){
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
     * @param inputLine
     * @param commands
     * @return
     */
    protected boolean switchOrRun(InputLine inputLine, CommonCommands commands) {
        boolean switchComponent = 1 < inputLine.getArgCount();

        CLIDriver cli = new CLIDriver(commands);
        cli.setEnv(getGlobalEnv());
        cli.setComponentManager(this);
        if(switchComponent){
            inputLine.removeArgAt(0); // removes original arg ("use")
            cli.execute(inputLine.removeArgAt(0)); // removes components before executing
        }else {
            cli.start();
        }
        return true;
    }


    protected boolean hasComponent(String componentName) {
        return componentName.equals(CLIENTS) ||
                componentName.equals(CLIENT_APPROVALS) ||
                componentName.equals(COPY)||
                componentName.equals(PARSER_COMMAND);
    }

    protected void runComponent(String componentName) throws Throwable {
        CommonCommands commonCommands = null;
        if (componentName.equals(PARSER_COMMAND)) {
            commonCommands = getNewParserCommands();
        }
        if (componentName.equals(CLIENTS)) {
            commonCommands = getNewClientStoreCommands();
        }
        if (componentName.equals(CLIENT_APPROVALS)) {
            commonCommands = getNewClientApprovalStoreCommands();
        }
        if (componentName.equals(COPY)) {
            commonCommands = getNewCopyCommands();
        }
        if (commonCommands != null) {
            CLIDriver cli = new CLIDriver(commonCommands);
            cli.start();

        }
    }

    public abstract ParserCommands getNewParserCommands() throws Throwable ;

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
        say(PARSER_COMMAND+ " - debug/use/try out the parser for scripting.\n");
        say("e.g.\n\nuse " + CLIENTS + "\n\nwill call up the client management component.");
        say("Type 'exit' or /q when you wish to exit the component and return to the main menu");
    }

}
