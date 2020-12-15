package edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.AbstractPayloadConfig;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.PayloadHandlerConfigImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXRecord;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting.OA2State;
import edu.uiuc.ncsa.qdl.exceptions.QDLException;
import edu.uiuc.ncsa.qdl.extensions.QDLFunction;
import edu.uiuc.ncsa.qdl.state.State;
import edu.uiuc.ncsa.qdl.variables.QDLNull;
import edu.uiuc.ncsa.qdl.variables.StemVariable;

import javax.servlet.http.HttpServletRequest;

/**
 * Superclass for the various token (id, access, refresh) handlers.  The way handlers work is a general init and
 * finish method are called (exposed here) and whatever configuration the user supplies is invoked in between these.
 * The assumption with QDL is that that automatic processing is being done in QDL, so all that is needed is that
 * standard init and finish methods.
 * <p>Created by Jeff Gaynor<br>
 * on 10/12/20 at  6:10 AM
 */
public abstract class TokenHandlerMethod implements QDLFunction {
    @Override
    public Object evaluate(Object[] objects, State state) {
        oa2State = checkState(state); // Fingers and toes, cast it to the right thing and set it.
        return null;  // dummy. This just sets up QDLFunction to be evaluated.
    }

    protected OA2State checkState(State state){
        if(state == null){
            throw new IllegalStateException("Error: No state was found");
        }
        if(!(state instanceof OA2State)){
            throw new IllegalArgumentException("Error: An instance of OA2State was expected, but one of type \"" + state.getClass().getCanonicalName() + "\" was found.");
        }
        return (OA2State)state;
    }

    boolean isInit = false;
    OA2State oa2State;

    protected PayloadHandlerConfigImpl getPayloadHandlerConfig() {
        if (payloadHandlerConfig == null) {
            payloadHandlerConfig = new PayloadHandlerConfigImpl(
                    getPayloadConfig(),
                    getSE(),
                    getTransaction(),
                    getTXRecord(),
                    getServletRequest());
        }
        return payloadHandlerConfig;

    }

    protected abstract AbstractPayloadConfig getPayloadConfig();

    PayloadHandlerConfigImpl payloadHandlerConfig;

    public TokenHandlerMethod() {

    }

    /**
     * Checks that the argument at argIndex is a stem. The name is sent along so the error message
     * can be more meaningful.
     * @param objects
     * @param name
     * @param argIndex
     * @return
     */
    protected StemVariable checkArg(Object[] objects, String name, int argIndex) {

        if(objects[1] == null || (objects[1] instanceof QDLNull)){
            // just make one
            return new StemVariable();
        }
        if (objects[1] instanceof StemVariable) {
            return (StemVariable) objects[argIndex];
        }
        throw new IllegalArgumentException("Error: " + name + " requires a stem argument #" + argIndex);
    }

    protected OA2ServiceTransaction getTransaction() {
        return oa2State.getTransaction();
    }

    protected TXRecord getTXRecord(){
        return oa2State.getTxRecord();
    }

    protected OA2Client getClient() {
        return getTransaction().getOA2Client();
    }

    protected HttpServletRequest getServletRequest() {
        return oa2State.getRequest();
    }

    protected OA2SE getSE() {
        return oa2State.getOa2se();
    }

    protected void handleException(Throwable throwable) throws RuntimeException {
        if (throwable instanceof RuntimeException) {
            throw (RuntimeException) throwable;
        }
        throw new QDLException(throwable);
    }


}
