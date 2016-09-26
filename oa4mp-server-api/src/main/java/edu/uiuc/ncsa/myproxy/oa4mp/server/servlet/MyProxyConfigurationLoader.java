package edu.uiuc.ncsa.myproxy.oa4mp.server.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.server.MyProxyFacadeProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;
import edu.uiuc.ncsa.security.core.configuration.Configurations;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.servlet.DBConfigLoader;
import org.apache.commons.configuration.tree.ConfigurationNode;

import java.util.LinkedList;
import java.util.List;

import static edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags.MYPROXY_SERVER_DN;
import static edu.uiuc.ncsa.security.core.configuration.Configurations.getFirstAttribute;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/4/15 at  2:19 PM
 */
public abstract class MyProxyConfigurationLoader<T extends AbstractEnvironment> extends DBConfigLoader<T> {
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

             } else {
                 // set up with defaults
                 mfp.add(new MyProxyFacadeProvider());
             }

         }
         return mfp;
     }

}
