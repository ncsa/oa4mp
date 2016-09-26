package edu.uiuc.ncsa.myproxy.client;

import edu.uiuc.ncsa.security.core.configuration.ConfigTest;
import edu.uiuc.ncsa.security.core.configuration.Configurations;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.XMLConfiguration;
import org.apache.commons.configuration.tree.ConfigurationNode;
import org.junit.Test;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/19/12 at  10:33 AM
 */
public class ClientConfigTest extends ConfigTest {
    @Test
    public void testConfig() throws Exception{
        ConfigurationNode cn = getConfig("sample");
        say("id = " +Configurations.getNodeValue(cn, "id"));
        printNodes(cn);
    }

    @Override
    protected XMLConfiguration getConfiguration() throws ConfigurationException {
        return getConfiguration("/client.xml");
    }

    @Override
    protected String getConfigurationType() {
        return "client";
    }

}
