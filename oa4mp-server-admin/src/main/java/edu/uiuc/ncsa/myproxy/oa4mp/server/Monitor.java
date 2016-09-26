package edu.uiuc.ncsa.myproxy.oa4mp.server;

import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientXMLTags;
import edu.uiuc.ncsa.myproxy.oa4mp.client.loader.AbstractClientLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.client.loader.ClientLoader;
import edu.uiuc.ncsa.security.core.exceptions.ServerRedirectException;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.servlet.AbstractServlet;
import edu.uiuc.ncsa.security.servlet.ServiceClient;
import edu.uiuc.ncsa.security.util.cli.CLITool;
import edu.uiuc.ncsa.security.util.mail.MailUtil;
import edu.uiuc.ncsa.security.util.mail.MailUtilProvider;
import org.apache.commons.cli.Options;
import org.apache.commons.configuration.tree.ConfigurationNode;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.List;

/**
 * Class that monitors a server. This will issue a call from the command line.
 * Each endpoint of an OA4MP server is pingable. Making an HTTP GET with the parameter "ping"
 * will return an HTTP 204 response (no body). Otherwise the operation will fail. The reason each endpoint
 * is ping-able is because it is possible to replace any endpoint (e.g. writing your own authorize endpoint)
 * and hence simply checking one of them, which is what older versions would do, is in sufficient. This monitor does
 * only check a single endpoint, but you can have multiple ones. The configuration is identical to that of
 * any other client. The basic ping now is against the access token endpoint, since various servers (OAuth 1.0a, OAuth 2.0)
 * may or may not have initialization or authorization endpoints that support this, such as in the case where there is
 * a custom authorization module.
 * <p>Created by Jeff Gaynor<br>
 * on 8/26/11 at  5:15 PM
 */
public class Monitor extends CLITool {
    @Override
    public void doIt() throws Exception {
        HashMap<String, String> map = new HashMap<>();
        map.put(AbstractServlet.PING_PARAMETER, "");
        info("Making initial request to service at " + serviceClient.host());
        try {
            // Quick comment: In the service client, a response with HTML status code of 204 (status=ok, no body) is
            // processed and if correct, returns a raw response of length zero. If another code occurs and there is
            // no body, then an exception is raised. This is why the check below is the right one for the current case.
            String response = serviceClient.getRawResponse(map);
            if (response.length() == 0) {
                // then all is ok. Maybe do some logging
                info("ping ok");
            } else {
                // moar logging
                warn("Ping failed to server " + serviceClient.host() + ". This ping works against servers that are version 3.0 or higher.");
                System.exit(1);
            }
        } catch (Throwable t) {
            error("ping failed to server " + serviceClient.host(), t);
            System.exit(1);
        }
        // From here on down is the older version for servers that do not support the ping command.

/*
        System.out.println(getClass().getSimpleName() + ".doIt: response=" + response);
        OA4MPService xService = new OA4MPService(getClientEnvironment());
        info("Making initial request to service at " + ((AddressableServer) xService.getEnvironment().getDelegationService().getAtServer()).getAddress());
        OA4MPResponse oa4mpResponse = xService.requestCert();
        info("got response, redirect uri = " + oa4mpResponse.getRedirect());
*/
    }

    public ClientEnvironment getClientEnvironment() throws Exception {
        return (ClientEnvironment) getEnvironment();
    }

    @Override
    public void initialize() throws Exception {
        super.initialize();
        // Allow for over-riding the log file from the command line.
        if (getLogfileName().equals(DEFAULT_LOG_FILE)) {
            setMyLogger(getEnvironment().getMyLogger());
        } else {
            File f = new File(getLogfileName());
            info("Setting up environment, log file = " + f.getAbsolutePath());
        }
        String cfgName = null;
        if (hasOption(CONFIG_NAME_OPTION, CONFIG_NAME_LONG_OPTION)) {
            cfgName = getCommandLine().getOptionValue(CONFIG_NAME_OPTION);
        }
        if (cfgName == null) {
            info("no named for a configuration given");
        } else {
            info("getting named configuration \"" + cfgName + "\"");
        }
        try {
            List list = getConfigurationNode().getChildren("mail");
            if (list.size() != 0) {
                mup = new MailUtilProvider((ConfigurationNode) list.get(0));

            }
        } catch (Throwable t) {
            info("Did not initialize a mail notification environment:" + t.getMessage());
        }
        serviceClient = ((AbstractClientLoader) getLoader()).createServiceClient(getClientEnvironment().getAccessTokenUri());
        info("Done with bootstrap.");
    }

    ServiceClient serviceClient;

    @Override
    public ConfigurationLoader<? extends AbstractEnvironment> getLoader() {
        return new ClientLoader(getConfigurationNode());
    }

    @Override
    public String getComponentName() {
        return ClientXMLTags.COMPONENT;
    }

    @Override
    public void help() {
        say("This is a command line tool to check that an OAuth for MyProxy server up and running.");
        defaultHelp(true);
        say("An example: \n");
        say("     java -jar monit.jar -cfg config.xml-v\n");
        File f = new File(DEFAULT_LOG_FILE);
        say("would use the properties file config.xml and print messages to the console. Output is in the local");
        say("directory in \"" + f.getAbsolutePath() + "\"");
    }


    MailUtilProvider mup = null;

    protected boolean mailNotificationsOn() {
        return mup != null;
    }

    public void sendNotification(Throwable t) {
        if (!mailNotificationsOn()) return;
        try {
            HashMap<String, String> replacements = new HashMap<String, String>();
            replacements.put("name", getClientEnvironment().getInitializeUri().toString());
            replacements.put("message", t.getMessage());
            replacements.put("host", InetAddress.getLocalHost().getCanonicalHostName());
            String st = null;
            if (t instanceof ServerRedirectException) {
                st = ((ServerRedirectException) t).getWebpage();
            } else {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                PrintWriter pw = new PrintWriter(baos);
                t.printStackTrace(pw);
                pw.flush();
                st = new String(baos.toByteArray());
                pw.close();
            }
            replacements.put("stacktrace", st);
            MailUtil mailUtil = mup.get();
            // log it all to the right place.
            mailUtil.setMyLogger(getMyLogger());
            mailUtil.sendMessage(replacements);
        } catch (Throwable throwable) {
            info("Could not send notification: " + t.getMessage());
            if (isVerbose()) {
                throwable.printStackTrace();
            }
        }

    }

    public static void main(String[] args) {
        Monitor monitor = new Monitor();
        try {
            monitor.run(args);
        } catch (Throwable e) {
            // Since this will probably be called only by a bash script, catch all errors and exceptions
            // then return a non-zero exit code
            if (monitor.isVerbose()) {
                e.printStackTrace();
            }
            monitor.getMyLogger().error("Error contacting server", e);
            monitor.sendNotification(e);
            System.exit(1);
        }
    }


    @Override
    protected Options getOptions() {
        Options options = super.getOptions();
        options.addOption(CONFIG_NAME_OPTION, CONFIG_NAME_LONG_OPTION, true,
                "the name of the configuration. " +
                        "Omitting this means there is exactly one and to use that.");
        return options;
    }
}
