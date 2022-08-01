package edu.uiuc.ncsa.oa4mp.delegation.client;

import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

import java.util.Map;

/**
 * Top-level client environment class. This contains all of the information read from
 * some configuration file for a client.
 * <p>Created by Jeff Gaynor<br>
 * on 3/11/14 at  4:45 PM
 */
public abstract class AbstractClientEnvironment extends AbstractEnvironment {
    public AbstractClientEnvironment() {
    }

    public AbstractClientEnvironment(MyLoggingFacade myLogger) {
        super(myLogger);
    }

    public AbstractClientEnvironment(MyLoggingFacade myLogger, Map<String, String> constants) {
        super(myLogger, constants);
    }

    /**
       * This is used in requests as the key for the cert request parameter
       */
      public static final String CERT_REQUEST_KEY = "certreq";
      /**
       * This is used in requests as the key for the cert lifetime parameter.
       */
      public static final String CERT_LIFETIME_KEY = "certlifetime";

}
