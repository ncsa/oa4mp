package org.oa4mp.delegation.server.request;

import org.oa4mp.delegation.common.services.Response;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on May 13, 2011 at  12:00:03 PM
 */
public interface IssuerResponse extends Response {
    /**
     * Write the result to the given response.
     */
    public void write(HttpServletResponse response) throws IOException;

    /**
     * There may be several ways that parameters come in for a request. It is up to the
     * implementation to parse them into key/value pairs and pass them back. Generally this
     * includes everything that the client got.
     *
     * @return
     */
    public Map<String, String> getParameters();
}
