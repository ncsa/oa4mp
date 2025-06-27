package org.oa4mp.myproxy.servlet;

import edu.uiuc.ncsa.myproxy.MyProxyServiceFacade;
import edu.uiuc.ncsa.myproxy.ServiceFacadeConfiguration;
import edu.uiuc.ncsa.security.core.configuration.Configurations;
import edu.uiuc.ncsa.security.core.configuration.provider.CfgEvent;
import edu.uiuc.ncsa.security.core.configuration.provider.HierarchicalConfigProvider;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.util.ssl.SSLConfigurationUtil;
import edu.uiuc.ncsa.security.util.ssl.SSLKeystoreConfiguration;
import org.apache.commons.configuration.tree.ConfigurationNode;
import org.oa4mp.server.api.OA4MPConfigTags;

import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/19/12 at  4:35 PM
 */
public class MyProxyFacadeProvider extends HierarchicalConfigProvider<MyProxyServiceFacade> implements OA4MPConfigTags {

    @Override
    protected boolean checkEvent(CfgEvent cfgEvent) {
        if (cfgEvent.getConfiguration().getName().equals(MYPROXY)) {
            setConfig(cfgEvent.getConfiguration());
            return true;
        }
        return false;
    }

    @Override
    public Object componentFound(CfgEvent configurationEvent) {
        if (checkEvent(configurationEvent)) {
            return get();
        }
        return null;
    }

    @Override
    public MyProxyServiceFacade get() {
        ServiceFacadeConfiguration sfc;
        HashMap<String, Integer> loas = new HashMap<String, Integer>();
        String localhostname = null;
        String serverDN = null;
        try {
            localhostname = java.net.InetAddress.getLocalHost().getCanonicalHostName();
        } catch (UnknownHostException e) {
            localhostname = "localhost";
        }
        int port = 7512; //start with default port.
        long socketTimeout = 0L; // start with default
        SSLKeystoreConfiguration sslKeystoreConfiguration = SSLConfigurationUtil.getSSLConfiguration(null, getConfig());
        if (getConfig() == null) {
            // No configuration, so use the defaults.
            sfc = new ServiceFacadeConfiguration(localhostname, port, socketTimeout, loas, serverDN);
            //   return new MyProxyServiceFacade(sfc);
        } else {
            String rawUseProxy = getAttribute(MYPROXY_USE_PROXY);
            if (!StringUtils.isTrivial(rawUseProxy)) {
                boolean useProxy = getBooleanAttribute(MYPROXY_USE_PROXY);
                if (useProxy) {
                    // If true, short circuit whole thing and return.
                    return new MyProxyServiceFacade(new ServiceFacadeConfiguration(true), sslKeystoreConfiguration);
                }
            }
            serverDN = getAttribute(MYPROXY_SERVER_DN);
            if (serverDN == null && hasDefaultServerDN()) {
                serverDN = getDefaultServerDN();
            }

            try {
                port = getIntAttribute(MYPROXY_PORT);
            } catch (Throwable t) {
                // do nothing. If the port is not given, use the default
            }
            try {
                socketTimeout = getIntAttribute(MYPROXY_SOCKET_TIMEOUT);
            } catch (Throwable t) {
                // do nix.
            }
            if (getAttribute(MYPROXY_HOST) != null) {
                localhostname = getAttribute(MYPROXY_HOST);
            }

            sfc = new ServiceFacadeConfiguration(localhostname, port, socketTimeout, loas, serverDN);

            List list = getConfig().getChildren(MYPROXY_LOA);
            if (!list.isEmpty()) {
                for (Object obj : list) {
                    ConfigurationNode cn = (ConfigurationNode) obj;
                    loas.put(Configurations.getFirstAttribute(cn, MYPROXY_LOA_NAME),
                            Integer.parseInt(Configurations.getFirstAttribute(cn, MYPROXY_LOA_PORT)));
                }
            }
        }
        // Unless there is something very exotic about your setup, a basic configuration that
        // points to the standard keystore available in java should be more than sufficient.
        return new MyProxyServiceFacade(sfc, sslKeystoreConfiguration);
    }

    public MyProxyFacadeProvider() {
    }

    public MyProxyFacadeProvider(ConfigurationNode config, String defaultServerDN) {
        super(config);
        this.defaultServerDN = defaultServerDN;
    }

    /**
     * Default constructor for no default server DN.
     *
     * @param config
     */
    public MyProxyFacadeProvider(ConfigurationNode config) {
        super(config);
    }

    public boolean hasDefaultServerDN() {
        return defaultServerDN != null;
    }

    /**
     * A default server DN to be used in cases where the MyProxy server's cert may contain this as an
     *
     * @return
     */
    public String getDefaultServerDN() {
        return defaultServerDN;
    }

    public void setDefaultServerDN(String defaultServerDN) {
        this.defaultServerDN = defaultServerDN;
    }

    String defaultServerDN = null;
}
