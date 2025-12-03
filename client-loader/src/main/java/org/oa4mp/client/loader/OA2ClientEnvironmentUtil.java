package org.oa4mp.client.loader;

import edu.uiuc.ncsa.security.core.cf.CFXMLConfigurations;
import org.oa4mp.client.api.ClientXMLTags;

import java.io.File;

/**
 * A utility to allow for loading the client environment from outside the servlet.
 * <p>Created by Jeff Gaynor<br>
 * on 3/5/13 at  12:14 PM
 */
public class OA2ClientEnvironmentUtil {
    public static OA2ClientEnvironment load(File configFile, String configName) throws Exception{
        return  (OA2ClientEnvironment)  new OA2CFClientLoader(CFXMLConfigurations.findConfiguration(configFile.getAbsolutePath(),
                ClientXMLTags.COMPONENT,
                configName)).load();
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
