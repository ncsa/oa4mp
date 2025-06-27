package org.oa4mp.myproxy.servlet;

import edu.uiuc.ncsa.security.core.configuration.Configurations;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import org.apache.commons.configuration.tree.ConfigurationNode;
import org.oa4mp.server.api.OA4MPConfigTags;
import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.loader.OA2ConfigurationLoader;

import java.util.LinkedList;
import java.util.List;

import static edu.uiuc.ncsa.security.core.configuration.Configurations.getFirstAttribute;
import static org.oa4mp.server.api.OA4MPConfigTags.MYPROXY_SERVER_DN;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/4/15 at  2:19 PM
 */
public abstract class MyProxyConfigurationLoader<T extends OA2SE> extends OA2ConfigurationLoader<T> {
    public MyProxyConfigurationLoader(ConfigurationNode node) {
        super(node);
    }
    protected LinkedList<MyProxyFacadeProvider> mfp = null;


    public MyProxyConfigurationLoader(ConfigurationNode node, MyLoggingFacade logger) {
        super(node, logger);
    }
    protected LinkedList<MyProxyFacadeProvider> getMyProxyFacadeProvider() {
         if (mfp == null) {
             mfp = new LinkedList<MyProxyFacadeProvider>();
             // This is the global default for all instances. It can be overridden below.
             String defaultDN = Configurations.getFirstAttribute(cn, MYPROXY_SERVER_DN);

             if (0 < cn.getChildrenCount(OA4MPConfigTags.MYPROXY)) {
                 List kids = cn.getChildren(OA4MPConfigTags.MYPROXY);
                 for (int i = 0; i < kids.size(); i++) {
                     ConfigurationNode currentNode = (ConfigurationNode) kids.get(i);
                     // Fix for CIL-196.
                     String currentDN  = getFirstAttribute(currentNode, MYPROXY_SERVER_DN);
                     mfp.add(new MyProxyFacadeProvider(((ConfigurationNode) kids.get(i)), (currentDN==null?defaultDN:currentDN)));
                 }
             }
         }
         return mfp;
     }

}
