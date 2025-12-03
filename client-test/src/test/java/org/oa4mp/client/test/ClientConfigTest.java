package org.oa4mp.client.test;

import edu.uiuc.ncsa.security.core.cf.CFBundle;
import edu.uiuc.ncsa.security.core.cf.CFNode;
import edu.uiuc.ncsa.security.core.configuration.ConfigTest;
import org.junit.Test;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/19/12 at  10:33 AM
 */
public class ClientConfigTest extends ConfigTest {
    @Test
    public void testConfig() throws Exception{
        CFNode cn = getConfig("sample");
        say("id = " +cn.getNodeContents("id"));
        print(cn);
    }

    @Override
    protected CFBundle getConfiguration() {
        return getConfiguration("/client.xml");
    }

    @Override
    protected String getConfigurationType() {
        return "client";
    }

}
