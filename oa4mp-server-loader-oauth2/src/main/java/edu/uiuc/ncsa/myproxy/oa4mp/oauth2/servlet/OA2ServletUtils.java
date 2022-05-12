package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.transactions.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXRecord;
import edu.uiuc.ncsa.qdl.exceptions.AssertionException;
import edu.uiuc.ncsa.qdl.exceptions.QDLExceptionWithTrace;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import edu.uiuc.ncsa.security.oauth_2_0.OA2ATException;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.ScriptRuntimeException;
import edu.uiuc.ncsa.security.storage.GenericStoreUtils;
import edu.uiuc.ncsa.security.storage.XMLMap;
import org.apache.http.HttpStatus;

/**
 * Utilities for various servlets. These handle the exceptions from the script runtime engine and perform
 * a full rollback. These are messy, but unavoidable.
 * <p>Created by Jeff Gaynor<br>
 * on 4/26/22 at  6:52 AM
 */
public class OA2ServletUtils {
    public static void handleScriptEngineException(Object callingObject,
                                                   OA2SE oa2SE,
                                                   Throwable t,
                                                   MetaDebugUtil debugger,
                                                   OA2ServiceTransaction transaction,
                                                   XMLMap tBackup) {
        handleScriptEngineException(callingObject, oa2SE, t, debugger, transaction, tBackup, null);

    }

    /**

     * @param callingObject
     * @param oa2SE
     * @param exception
     * @param debugger
     * @param transaction
     * @param tBackup
     * @param txRecord
     */
    public static void handleScriptEngineException(Object callingObject,
                                                   OA2SE oa2SE,
                                                   Throwable exception,
                                                   MetaDebugUtil debugger,
                                                   OA2ServiceTransaction transaction,
                                                   XMLMap tBackup,
                                                   TXRecord txRecord) {
        rollback(oa2SE, tBackup, txRecord); // everything here gets a rollback
        if (exception instanceof QDLExceptionWithTrace) {
            // CIL-1267 make sure error propagate.
            // This can happen if something very deep in the stack (non QDL) blows up and QDL
            // has caught it.

            QDLExceptionWithTrace qdlExceptionWithTrace = (QDLExceptionWithTrace) exception;
            Throwable throwable = qdlExceptionWithTrace;
            if (qdlExceptionWithTrace.getCause() != null) {
                throwable = qdlExceptionWithTrace.getCause();
            }
            debugger.error(callingObject, "Server exception \"" + throwable.getMessage() + "\"", exception);
            throw new OA2ATException(OA2Errors.SERVER_ERROR,
                    "internal error:" + exception.getMessage(),
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    transaction.getRequestState());
        }
        if(exception instanceof AssertionException){
            // they passed a bad argument to a QDL script
            AssertionException assertionException = (AssertionException)exception;
            debugger.trace(callingObject, "assertion exception \"" + assertionException.getMessage() + "\"");
            throw new OA2ATException(OA2Errors.INVALID_REQUEST,
                    assertionException.getMessage(),
                    HttpStatus.SC_BAD_REQUEST,
                    transaction.getRequestState());
        }
        if(exception instanceof ScriptRuntimeException){
            // QDL script threw an exception. Usually this means there is missing information from e.g. LDAP.
            // Let the user try and figure everything out and try again.
            ScriptRuntimeException sre = (ScriptRuntimeException) exception;
            debugger.trace(callingObject, "script runtime exception \"" + sre.getMessage() + "\"");
            throw new OA2ATException(sre.getRequestedType(), sre.getMessage(), sre.getStatus(), transaction.getRequestState());
        }
        if(exception instanceof IllegalAccessException){
            // *Possible* from servlet. Mostly catching it here since otherwise the user gets something
            // completely confusing.
            debugger.trace(callingObject, "internal illegal access exception \"" + exception.getMessage() + "\"", exception);
            // Most generic exception possible.
            throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT,
                    "access denied",
                    transaction.getRequestState());
        }

        // Everything else. Allow to fix the problem. Proceeding means that the transaction will complete
        // and the old tokens will be invalid, replaced by new ones.
        debugger.trace(callingObject, "Unable to update claims on token refresh", exception);
        debugger.warn(callingObject, "Unable to update claims on token refresh: \"" + exception.getMessage() + "\"");
        throw new OA2ATException(OA2Errors.INVALID_REQUEST,
                "invalid request",
                HttpStatus.SC_BAD_REQUEST,
                transaction.getRequestState());

    }

    protected static void rollback(OA2SE oa2SE, XMLMap backup) {
        rollback(oa2SE, backup, null);
    }

    protected static void rollback(OA2SE oa2SE, XMLMap backup, TXRecord txRecord) {
        GenericStoreUtils.fromXMLAndSave(oa2SE.getTransactionStore(), backup);
        if (txRecord != null) {
            oa2SE.getTxStore().remove(txRecord.getIdentifier());
        }
    }
}
