package edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims;

import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

import java.util.Collection;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/19/16 at  11:26 AM
 */
public class ClaimSourceFactoryRequest {
    public Collection<String> getScopes() {
        return scopes;
    }

    public void setScopes(Collection<String> scopes) {
        this.scopes = scopes;
    }

    public MyLoggingFacade getLogger() {
        return logger;
    }

    public void setLogger(MyLoggingFacade logger) {
        this.logger = logger;
    }

    Collection<String> scopes;
    MyLoggingFacade logger;

    public ClaimSourceConfiguration getConfiguration() {
        return configuration;
    }

    public void setConfiguration(ClaimSourceConfiguration configuration) {
        this.configuration = configuration;
    }

    ClaimSourceConfiguration configuration;

    public ClaimSourceFactoryRequest(MyLoggingFacade logger, ClaimSourceConfiguration config, Collection<String> scopes) {
        this.logger = logger;
        this.scopes = scopes;
        this.configuration = config;
    }

    @Override
    public String toString() {
        return "ClaimSourceFactoryRequest{" +
                "configuration=" + configuration +
                ", scopes=" + scopes +
                ", logger=" + logger +
                '}';
    }
}