package org.oa4mp.client.loader;

import org.oa4mp.client.api.ClientXMLTags;
import edu.uiuc.ncsa.security.util.configuration.XMLConfigUtil;

import java.io.File;

/**
 * A utility to allow for loading the client environment from outside the servlet.
 * <p>Created by Jeff Gaynor<br>
 * on 3/5/13 at  12:14 PM
 */
public class OA2ClientEnvironmentUtil {
    public static OA2ClientEnvironment load(File configFile, String configName) throws Exception{
        return (OA2ClientEnvironment) new OA2ClientLoader(XMLConfigUtil.findConfiguration(configFile.getAbsolutePath(),
                configName, ClientXMLTags.COMPONENT)).load();
    }

    /**
     * For the case that the configuration file has a single configuration in it. This does not require a name
     * to be loaded.
     * @param configFile
     * @return
     * @throws Exception
     */
    public static OA2ClientEnvironment load(File configFile) throws Exception{
        return load(configFile, null);
    }

}
