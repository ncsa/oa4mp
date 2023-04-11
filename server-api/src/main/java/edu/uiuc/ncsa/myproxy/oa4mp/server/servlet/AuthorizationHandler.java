package edu.uiuc.ncsa.myproxy.oa4mp.server.servlet;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Marker interface for things that handle authorization.
 * <p>Created by Jeff Gaynor<br>
 * on 2/17/14 at  10:48 AM
 */
public interface AuthorizationHandler {
    public void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable;
}
