package edu.uiuc.ncsa.myproxy.oa4mp.server;

import edu.uiuc.ncsa.myproxy.MyProxyServiceFacade;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * An environment that needs to have my proxy services available.
 * <p>Created by Jeff Gaynor<br>
 * on 9/4/15 at  11:00 AM
 */
public class MyProxyServiceEnvironment extends AbstractEnvironment {
    public MyProxyServiceEnvironment() {
    }

    public MyProxyServiceEnvironment(MyLoggingFacade myLogger,
                                     List<MyProxyFacadeProvider> mfp
                                     ) {
        super(myLogger);
        this.mfps = mfp;
    }

    public MyProxyServiceEnvironment(MyLoggingFacade myLogger,
                                     List<MyProxyFacadeProvider> mfp,
                                     Map<String, String> constants) {
        super(myLogger, constants);
        this.mfps = mfp;

    }

    List<MyProxyFacadeProvider> mfps;

    protected List<MyProxyServiceFacade> myProxyServices;

    public List<MyProxyServiceFacade> getMyProxyServices() {
        if (myProxyServices == null) {
            myProxyServices = new LinkedList<MyProxyServiceFacade>();
            // loop through each found component
            for (MyProxyFacadeProvider m : mfps) {
                myProxyServices.add(m.get());
            }
            return myProxyServices;
        }
        return myProxyServices;
    }
}
