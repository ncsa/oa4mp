package edu.uiuc.ncsa.myproxy.oa4mp.server.servlet;

import edu.uiuc.ncsa.security.servlet.PresentableState;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * An object for passing around the state variable and anything else needed.
 * <p>Created by Jeff Gaynor<br>
 * on 10/25/11 at  10:45 AM
 */
public class PresentationState implements PresentableState {
    public PresentationState(int state, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse
    ) {
        this.state = state;
        request = httpServletRequest;
        response = httpServletResponse;
    }

    public int getState() {
        return state;
    }

    public void setState(int state) {
        this.state = state;
    }

    int state;
    HttpServletRequest request;
    HttpServletResponse response;

    public HttpServletRequest getRequest() {
        return request;
    }

    public HttpServletResponse getResponse() {
        return response;
    }

}
