package org.oa4mp.server.admin.oauth2.base;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.util.cli.*;
import org.oa4mp.server.admin.oauth2.tools.TransactionStoreCommands;
import org.oa4mp.server.api.OA4MPConfigTags;
import org.oa4mp.server.api.ServiceEnvironment;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/27/15 at  1:49 PM
 */
public abstract class BaseCommands2 extends ConfigurableCommandsImpl2 implements ComponentManager {

    public static final String CLIENTS = "clients";
    public static final String CLIENT_APPROVALS = "approvals";
    public static final String COPY = "copy";
    public String TRANSACTION_COMMAND = "transactions";
    protected Map<String, CLIDriver> drivers = new HashMap<>();

    //protected List<String> components = new ArrayList<>();

    protected boolean showHeader = true;
    protected boolean showLogo = true;

    @Override
    public void initialize() {
        try {
            if (drivers.isEmpty()) {
                drivers.put(CLIENTS, createCLIDriver(getClientCommands()));
                drivers.put(CLIENT_APPROVALS, createCLIDriver(getClientApprovalCommands()));
                drivers.put(TRANSACTION_COMMAND, createCLIDriver(getTransactionCommands()));
            }
        } catch (Throwable t) {
            if (t instanceof RuntimeException) {
                throw (RuntimeException) t;
            }
            throw new GeneralException("Unable to initialize CLI components", t);
        }
    }


    public Set<String> listComponents() {
        return drivers.keySet();
    }

    public abstract void about();

    public abstract ClientStoreCommands getClientCommands() throws Throwable;

    public abstract CopyCommands getCopyCommands() throws Throwable;

    protected abstract TransactionStoreCommands getTransactionCommands() throws Throwable;

    public BaseCommands2(CLIDriver driver) {
        super(driver);
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
    protected void startup(String[] args) throws Throwable {
        bootstrap(new InputLine(args));

    }



    public ServiceEnvironment getServiceEnvironment() throws Exception {
        return (ServiceEnvironment) getEnvironment();
    }


    ClientApprovalStoreCommands clientApprovalStoreCommands = null;
    public ClientApprovalStoreCommands getClientApprovalCommands() throws Throwable {
        if(clientApprovalStoreCommands == null) {
            clientApprovalStoreCommands = new ClientApprovalStoreCommands(new CLIDriver(), "  ", getServiceEnvironment().getClientApprovalStore());
            clientApprovalStoreCommands.setEnvironment(getEnvironment());
            configureCommands(getDriver(), clientApprovalStoreCommands);
            clientApprovalStoreCommands.initHelp();
        }
        return clientApprovalStoreCommands;

    }

    @Override
    public boolean use(InputLine inputLine) throws Throwable {
        CommonCommands2 commands = null;

        if (inputLine.hasArg(CLIENTS)) {
            commands = getClientCommands();
        }
        if (inputLine.hasArg(CLIENT_APPROVALS)) {
            commands = getClientApprovalCommands();
        }

        if (inputLine.hasArg(TRANSACTION_COMMAND)) {
            commands = getTransactionCommands();
        }
        if (commands != null) {
            return switchOrRun(inputLine, commands);
        }

        if (super.use(inputLine)) {
            return true;
        }
        say("could not find the component named \"" + inputLine.getArg(1) + "\". Type 'use --help' for help");

        return false;
    }


    protected CLIDriver createCLIDriver(CommonCommands2 commands) {
        CLIDriver cli = new CLIDriver();

        cli.setIOInterface(getDriver().getIOInterface());
        cli.getHelpUtil().addHelp(getHelpUtil());
        try {
            commands.initialize();
        } catch (Throwable e) {
            if(getDriver().isTraceOn()) {
                e.printStackTrace();
            }
            if(e instanceof RuntimeException) {
                throw (RuntimeException)e;
            }
            throw new GeneralException(e);
        }
        cli.addCommands(commands);
        cli.setEnv(getDriver().getEnv());
        cli.setComponentManager(this);
        return cli;
    }

    protected boolean hasComponent(String componentName) {
        return componentName.equals(CLIENTS) ||
                componentName.equals(CLIENT_APPROVALS) ||
                componentName.equals(COPY);
    }

    protected void runComponent(String componentName) throws Throwable {
        CommonCommands2 commonCommands = null;

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
