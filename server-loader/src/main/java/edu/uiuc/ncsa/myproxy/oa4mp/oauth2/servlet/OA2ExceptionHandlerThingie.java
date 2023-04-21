package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.oa4mp.delegation.common.storage.BaseClient;
import edu.uiuc.ncsa.security.servlet.ExceptionHandlerThingie;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/20/23 at  1:41 PM
 */
public class OA2ExceptionHandlerThingie extends ExceptionHandlerThingie {
    public OA2ExceptionHandlerThingie(Throwable throwable,
                                      HttpServletRequest request,
                                      HttpServletResponse response, BaseClient client) {
        super(throwable, request, response);
        this.client = client;


    }
    public boolean hasClient(){
        return client!=null;
    }
    BaseClient client;
}
