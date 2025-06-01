package org.oa4mp.server.loader.qdl.claims;

import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.claims.AbstractPayloadConfig;
import org.oa4mp.server.loader.oauth2.claims.PayloadHandlerConfigImpl;
import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.loader.oauth2.storage.transactions.OA2ServiceTransaction;
import org.oa4mp.server.loader.oauth2.storage.tx.TXRecord;
import org.oa4mp.server.loader.qdl.scripting.OA2State;
import org.qdl_lang.exceptions.QDLException;
import org.qdl_lang.extensions.QDLFunction;
import org.qdl_lang.state.State;
import org.qdl_lang.variables.QDLStem;
import org.qdl_lang.variables.values.QDLValue;

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
    public QDLValue evaluate(QDLValue[] objects, State state) {
        oa2State = checkState(state); // Fingers and toes, cast it to the right thing and set it.
        return null;  // dummy. This just sets up QDLFunction to be evaluated.
    }

    protected OA2State checkState(State state){
        if(state == null){
            throw new IllegalStateException("No state was found");
        }
        if(!(state instanceof OA2State)){
            throw new IllegalArgumentException(" An instance of OA2State was expected, but one of type \"" + state.getClass().getCanonicalName() + "\" was found.");
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
                    getClient(),
                    getTXRecord(),
                    getServletRequest());
        }
        return payloadHandlerConfig;

    }

    protected abstract AbstractPayloadConfig getPayloadConfig();

    PayloadHandlerConfigImpl payloadHandlerConfig;

    public TokenHandlerMethod(OA2State oa2State) {
        this.oa2State = oa2State;

    }

    /**
     * Checks that the argument at argIndex is a stem. The name is sent along so the error message
     * can be more meaningful.
     * @param objects
     * @param name
     * @param argIndex
     * @return
     */
    protected QDLStem checkArg(QDLValue[] objects, String name, int argIndex) {

        if(objects[argIndex] == null || (objects[argIndex].isNull())){
            // just make one
            return new QDLStem();
        }
        if (objects[argIndex].isStem()) {
            return objects[argIndex].asStem();
        }
        throw new IllegalArgumentException(name + " requires a stem argument #" + argIndex);
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
