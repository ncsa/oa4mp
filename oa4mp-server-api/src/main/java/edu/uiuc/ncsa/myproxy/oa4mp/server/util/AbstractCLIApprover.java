package edu.uiuc.ncsa.myproxy.oa4mp.server.util;

import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceEnvironmentImpl;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.util.cli.CLITool;
import org.apache.commons.cli.Options;

import java.io.*;
import java.util.Date;
import java.util.LinkedList;
import java.util.Set;

import static edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags.COMPONENT;

/**
 * A command line approver. This has a couple of modes of operation.
 * <UL>
 * <LI>Immediate updates for non-memory store. If you commit a change, it is done instantly</LI>
 * <LI>Polling mode. A directory is set aside to store the pending approvals. The server polls this at
 * intervals and updates it store. This is especially useful for memory stores.</LI>
 * </UL>
 * <H2>Use</H2>
 * You should invoke this from the command line and specify the server configuration file. You will have to run this with
 * sufficient permissions to read that file, which probably means running this as root.
 * <H3>Running it from maven</H3>
 * To run this from maven directly, you need to follow these three steps:
 * <OL>
 * <LI>run <b><code>mvn compile</code></b> from the command line to compile it </LI>
 * <LI>Issue <br><Br><b><code>mvn exec:java -Dexec.mainClass="edu.uiuc.ncsa.myproxy.oa4mp.server.util.CLIApprover" -Dexec.args="-cfg /path/to/config.xml  -name config-name"
 * </code></b><br>r></LI>
 * <LI>Follow the on-screen prompts.</LI>
 * </OL>
 * <h3>Custom versions</h3>
 * This requires the right runtime {@link edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceEnvironment}, which is normally loaded using a
 * {@link ConfigurationLoader}.
 *
 * <p>Created by Jeff Gaynor<br>
 * on 2/24/12 at  2:40 PM
 */
public abstract class AbstractCLIApprover extends CLITool {
  public static final String ANONYMOUS = "anonymous";

    public static class ClientApprovalThread extends Thread {
        public ClientApprovalThread(MyLoggingFacade myLogger, ServiceEnvironmentImpl se2, File pollingDir, Long pollingInterval) {
            this.logger = myLogger;
            this.pollingDir = pollingDir;
            this.pollingInterval = pollingInterval;
            this.se = se2;
        }

        MyLoggingFacade logger;

        void info(Object x) {
            if (logger != null) {
                logger.info(x.toString());
            }
        }

        File pollingDir = null;
        /**
         * Milliseconds to sleep between tries Default is 60000 or 1 minute.
         */
        Long pollingInterval = 60000L;
        ServiceEnvironmentImpl se;

        public boolean isStopThread() {
            return stopThread;
        }

        public void setStopThread(boolean stopThread) {
            this.stopThread = stopThread;
        }

        boolean stopThread = false;

        public File getPollingDirectory() {
            return pollingDir;
        }

        public long getPollingInterval() {
            return pollingInterval;
        }

        @Override
        public void run() {
            try {
                info("starting client approval polling");
                while (!isStopThread()) {
                    if (pollingDir != null) {
                        File[] files = pollingDir.listFiles(new FilenameFilter() {
                            @Override
                            public boolean accept(File dir, String name) {
                                if (name.endsWith(TEMP_FILE_SUFFIX)) {
                                    return true;
                                }
                                return false;
                            }
                        });
                        for (File f : files) {
                            try {
                                info(getClass().getSimpleName() + ": Checking file " + f);
                                FileInputStream fis = new FileInputStream(f);
                                ObjectInputStream ois = new ObjectInputStream(fis);

                                ClientApproval ca = (ClientApproval) ois.readObject();
                                ois.close();

                                info("processing id =\"" + ca.getIdentifierString() + "\", approver is \"" + ca.getApprover() + "\"");
                                Client c = (Client) se.getClientStore().get(ca.getIdentifier()); // try and see if it really corresponds to a client
                                if (c != null) {
                                    se.getClientApprovalStore().save(ca);
                                    f.delete();
                                } else {
                                    logger.warn("Error! An attempt to alter client with id \"" + ca.getIdentifierString() + "\" was made, but no such client was found.");
                                }
                            } catch (Throwable t) {
                                // if not a serialized file, ignore it.
                            }
                            sleep(pollingInterval);
                        }
                    }
                }
            } catch (InterruptedException e) {
                setStopThread(true);
                info("Stopping client approval polling thread...");
                return;
            }
        }
    }

    public final static String POLLING_INTERVAL = "pollingInterval";
    public final static String POLLING_DIRECTORY = "pollingDirectory";
    public final static String TEMP_FILE_PREFIX = "clientApproval";
    public final static String TEMP_FILE_SUFFIX = ".ca";
    public final static String ID_DELIMITER = "/";

    ServiceEnvironmentImpl se;


    @Override
    public void doIt() throws Exception {
        Set keys = se.getClientApprovalStore().keySet();
        LinkedList<ClientApproval> linkedList = new LinkedList<ClientApproval>();
        info("starting approval");
        int i = 0;
        for (Object k : keys) {
            ClientApproval ca = (ClientApproval) se.getClientApprovalStore().get(k);
            linkedList.add(ca);
            say((i++) + ". " + (ca.isApproved() ? "(A) " : "(D) ") + linkedList.getLast().getIdentifierString());
        }
        if (linkedList.isEmpty()) {
            say("(No entries found. You will need to manually enter the id.)");
        }

        boolean keepAsking = true;
        String inString;
        ClientApproval ca = null;
        while (keepAsking) {
            say("Enter the number of the client to approve or disapprove, OR, enter an id, starting with a " + ID_DELIMITER);

            inString = readline();

            if (inString.startsWith(ID_DELIMITER)) {
                ca = new ClientApproval(new BasicIdentifier(inString.substring(ID_DELIMITER.length())));
                keepAsking = false;
            } else {
                try {
                    int index = Integer.parseInt(inString);
                    if (0 <= index && index < linkedList.size()) {
                        ca = linkedList.get(index);
                        keepAsking = false;
                    } else {
                        say("Sorry, that index is out of range. Try again.");
                    }
                } catch (NumberFormatException xx) {
                    boolean noInput = inString == null || inString.length()==0;
                    say("Woops. Didn't understand " + (noInput?"(empty)":"\"" + inString+"\"") + ". Try again.");
                }
            }
        }

        if (ca == null) {
            // future proof. Should never happen.
            warn("No client approval found. Aborting session");
            throw new GeneralException("Internal error: Somehow the client approval was not found. Fix that.");
        }
        Client client = (Client) se.getClientStore().get(ca.getIdentifier());
        if(client == null){
            info("No client found for the given identifier. Aborting.");
            say("no client found for the id. You probably want to fix that.\nexiting...");
            return;
        }else{
            say("You have chosen the following client");
            say(formatClient(client));
        }
        say("Enter your approver name [" + ANONYMOUS + "]:");
        inString = readline();
        ca.setApproved(true);
        if (inString == null || 0 == inString.length()) {
            ca.setApprover(ANONYMOUS);
        } else {
            ca.setApprover(inString);
        }
        info("Approver is identifier as " + ca.getApprover());
        say("Enter Approve or Deny (A/D) [D]");
        inString = readline();
        if (inString != null && inString.toLowerCase().equals("a")) {
            ca.setApproved(true);
        }
        info("Approver " + (ca.isApproved()?"denies":"allows") + " approval.");
        say("Commit changes? (y/n)");
        inString = readline();
        if (!inString.toLowerCase().equals("y")) {
            info("Approval aborted manually. No changes saved.");
            say("You didn't explicitly say to save it -- operation aborted.\nexiting...");
            return;
        }
        ca.setApprovalTimestamp(new Date()); //update timestamp to now.
        if (pollingDir != null) {
            // use polling
            File tempFile = File.createTempFile(TEMP_FILE_PREFIX, TEMP_FILE_SUFFIX, pollingDir);
            FileOutputStream fos = new FileOutputStream(tempFile);
            ObjectOutputStream oos = new ObjectOutputStream(fos);
            oos.writeObject(ca);
            fos.flush();
            fos.close();
        } else {
            // do the approval directly
            se.getClientApprovalStore().save(ca);
        }
        info("Approval for client with id \"" + ca.getIdentifierString() + "\" finished.");
    }


    protected String formatClient(Client client){
        String out = "";
        out = out + "  Name=\"" + client.getName() + "\"\n";
        out = out + "  email=\"" + client.getEmail() + "\"\n";
        out = out + "  home uri=\"" + client.getHomeUri() + "\"\n";
        out = out + "  error uri=\"" + client.getErrorUri() + "\"\n";
        return out;
    }

    @Override
    public String getComponentName() {
        return COMPONENT;
    }
    long pollingInt = 60000L;

    File pollingDir = null;


    @Override
    protected Options getOptions() {
        Options options = super.getOptions();
        options.addOption(CONFIG_NAME_OPTION, CONFIG_NAME_LONG_OPTION, true, "the name of the configuration. Omitting this means there is exactly one and to use that.");
        return options;
    }

    @Override
    public void help() {
        say("A command line tool to approve client requests");
        say("usage: " + getClass().getSimpleName() +" options");
        defaultHelp(true);
        say("Where the options are given as -x (fnord) = short option, (long option), and [] = optional. Other options: ");
        say("  [-" + CONFIG_NAME_OPTION + " (-" + CONFIG_NAME_LONG_OPTION + ") -- set the name of the configuration.]");
        say("If the configuration name is omitted, it is assumed there is exactly one in the given file and that is to be used.");
    }

}
