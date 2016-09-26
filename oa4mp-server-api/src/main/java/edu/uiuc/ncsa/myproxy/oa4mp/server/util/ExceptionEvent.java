package edu.uiuc.ncsa.myproxy.oa4mp.server.util;

import edu.uiuc.ncsa.security.servlet.NotificationEvent;

import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/18/12 at  11:26 AM
 */
public class ExceptionEvent extends NotificationEvent {
    Throwable throwable;

    public ExceptionEvent(Object source, Throwable throwable, Map<String,String> state) {
        super(source);
        this.throwable = throwable;
        this.state = state;
    }
    public Throwable getThrowable(){
        return throwable;
    }

    public Map<String, String> getState() {
        return state;
    }

    public void setState(Map<String, String> state) {
        this.state = state;
    }

    /**
     * The internal state of the servlet or calling agent. This is a set of key value pairs
     * that will be passed to a message template.
     */
    Map<String,String> state;

}
