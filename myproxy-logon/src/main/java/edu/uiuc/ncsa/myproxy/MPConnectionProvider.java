package edu.uiuc.ncsa.myproxy;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.ConnectionException;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

/**
 * A class that performs certain operations on sets of {@link MyProxyServiceFacade}s
 * and returns an open {@link MyProxyConnectable}. This is designed to look at
 * a list of facades and hand back the first that succeeds or, if all configured MyProxy servers
 * fail, this will fail.
 * <p/>
 * <p>Created by Jeff Gaynor<br>
 * on 3/16/15 at  2:49 PM
 */
public class MPConnectionProvider<T extends MyProxyConnectable> implements javax.inject.Provider<T> {
    // This class fixes CIL-120: multiple host failover of MyProxy servers.
    public MPConnectionProvider(MyLoggingFacade logger, List<MyProxyServiceFacade> facades) {
        this.facades = facades;
        this.logger = logger;
    }

    public MPConnectionProvider( List<MyProxyServiceFacade> facades) {
        this(null, facades);
      }
    protected void info(String x){
        if(logger != null){
            logger.info(x);
        }
    }

    protected void warn(String x){
        if(logger != null){
            logger.warn(x);
        }
    }
    List<MyProxyServiceFacade> facades;
    MyLoggingFacade logger;


    /**
     * Convenience constructor for a single facade
     * @param logger
     * @param facade
     */
    public MPConnectionProvider(MyLoggingFacade logger, MyProxyServiceFacade facade) {
        this.facades = new ArrayList<MyProxyServiceFacade>();
        this.facades.add(facade);
        this.logger = logger;
    }

    public MPConnectionProvider(MyProxyServiceFacade facade) {
        this.facades = new ArrayList<MyProxyServiceFacade>();
        this.facades.add(facade);
    }

    /**
     * Convenience method. A random identifier is assigned and the loa is assumed to be null.
     *
     * @param userName
     * @param password
     * @param lifetime
     * @return
     * @throws GeneralSecurityException
     */
    public T findConnection(String userName,
                            String password,
                            long lifetime) throws GeneralSecurityException {
        return findConnection(BasicIdentifier.randomID(), userName, password, null, lifetime);
    }

    @Override
    public T get() {
        return null;
    }

    // Fixes CIL-120, related to CIL-132

    public T findConnection(Identifier identifier,
                            String userName,
                            String password,
                            String loa,
                            long lifetime) throws GeneralSecurityException {
        T mpc = null;
        Throwable lastException = null;

        ArrayList<String> failures = new ArrayList<>();
        for (MyProxyServiceFacade facade : facades) {
            javax.inject.Provider<MyProxyConnectable> mpSingleConnectionProvider = null;
            try {
                mpSingleConnectionProvider = new MPSingleConnectionProvider<>(logger, userName, password, loa, lifetime, facade);
            } catch (IOException e) {
                warn("Got IOException connecting to MyProxy:" + e.getMessage());
                throw new GeneralException("IOException getting MyProxy provider:" + e.getMessage(), e);
            }
            mpc = (T) mpSingleConnectionProvider.get();
            mpc.setIdentifier(identifier);
            try {
                mpc.open();
                mpc.setIdentifier(identifier);
                // if this succeeds, print out a message

                logFailures("Failures connecting to MyProxy:", failures);
                info("MyProxy logon connection succeeded to " + facade.getFacadeConfiguration().getHostname());

                return mpc;
            } catch (ConnectionException cx) {
                String x;
                Throwable t = cx;
                Throwable lastCause = cx;
                while (t != null) {
                    lastCause = t;
                    t = t.getCause();
                }
                x = facade.getFacadeConfiguration().getHostname() + ": " + lastCause.getMessage(); // better message
                info("Error -- MyProxy logon failed for " + x.replace("\n", " "));
                failures.add(x);
                //info("Benign failure connecting to MyProxy: " + cx.getMessage());
                lastException = cx;
            }
        }


        logFailures("No usable MyProxy service found:", failures);
        info("MyProxy logon connection failed");
        if (lastException instanceof NoUsableMyProxyServerFoundException) {
            throw (NoUsableMyProxyServerFoundException) lastException;
        }
        throw new NoUsableMyProxyServerFoundException("Error: No usable MyProxy service found.", (lastException.getCause() == null ? lastException : lastException.getCause()));

    }

    private void logFailures(String msg, ArrayList<String> failures) {
        if (failures.size() != 0) {
            String out = "";
            for (String s : failures) {
                s = s.replace("\n", ", "); // some message come with embedded linefeeds.
                out = out + "\n       * " + s; // pads on left with blanks.
            }
            info("\n" + msg + out);
        }
    }

}
