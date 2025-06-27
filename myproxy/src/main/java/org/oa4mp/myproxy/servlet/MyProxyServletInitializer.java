package org.oa4mp.myproxy.servlet;

import edu.uiuc.ncsa.myproxy.MyProxyConnectable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.cache.Cache;
import edu.uiuc.ncsa.security.core.cache.CachedObject;
import edu.uiuc.ncsa.security.core.cache.Cleanup;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import org.oa4mp.server.api.util.ConnectionCacheRetentionPolicy;
import org.oa4mp.server.loader.oauth2.loader.OA2ServletInitializer;

import javax.servlet.ServletException;
import java.util.List;

public class MyProxyServletInitializer extends OA2ServletInitializer {
    @Override
    public void init() throws ServletException {
        if (isInitRun) return;
        isInitRun = true;
        super.init();

        MyProxyServiceEnvironment MPSE = (MyProxyServiceEnvironment) getEnvironment();
        Cleanup<Identifier, CachedObject> myproxyConnectionCleanup = MyProxyServlet.myproxyConnectionCleanup;

        if (!MPSE.getMyProxyServices().isEmpty() &&  myproxyConnectionCleanup == null) {
            myproxyConnectionCleanup = new Cleanup<Identifier, CachedObject>(MPSE.getMyLogger(), "myproxy connection cleanup") {
                @Override
                public List<CachedObject> age() {
                    List<CachedObject> x = super.age();
                    // by this point is has been removed from the cache. Rest of this
                    // is just trying to clean up afterwards.
                    for (CachedObject co : x) {
                        Object mp = co.getValue();
                        if (mp instanceof MyProxyConnectable) {
                            try {
                                ((MyProxyConnectable) mp).close();
                            } catch (Throwable t) {
                                // don't care if it fails, get rid of it.
                            }
                        }

                    }
                    return x;
                }
            };
            MyProxyServlet.myproxyConnectionCleanup = myproxyConnectionCleanup; // set it in the servlet
            // Set the cleanup interval much higher than the default (1 minute). We don't service
            // MyProxy requests much anymore, so it can be set a lot lower.
            MyProxyServlet.myproxyConnectionCleanup.setCleanupInterval(6 * 3600 * 1000L);
            DebugUtil.trace(this, "setting MyProxy connection cleanup interval to 6 hours.");
            myproxyConnectionCleanup.setStopThread(false);
            Cache myproxyConnectionCache = MyProxyServlet.myproxyConnectionCache;

            if (myproxyConnectionCache == null) {
                myproxyConnectionCache = new Cache();
                MyProxyServlet.myproxyConnectionCache = myproxyConnectionCache; // set it in the servlet
            }

            myproxyConnectionCleanup.setMap(myproxyConnectionCache);
            myproxyConnectionCleanup.addRetentionPolicy(new ConnectionCacheRetentionPolicy(myproxyConnectionCache, MPSE.getTransactionStore()));
            myproxyConnectionCleanup.start();

            MPSE.getMyLogger().info("Starting myproxy connection cache cleanup thread");
        }

        if (MyProxyServlet.myproxyConnectionCleanup != null) {
            if (MPSE.hasCleanupAlarms()) {
                MyProxyServlet.myproxyConnectionCleanup.setAlarms(MPSE.getCleanupAlarms());
            } else {
                MyProxyServlet.myproxyConnectionCleanup.setCleanupInterval(MPSE.getCleanupInterval());
            }
        }
    }
}
