package edu.uiuc.ncsa.oa4mp.delegation.common.servlet;

/**
 * A Filter pattern for working with servlets. Every servlet that can/does work with transactions
 * will invoke these methods as needed. Do recall that the servlet will still have all the
 * machinery from its {@link edu.uiuc.ncsa.security.core.util.AbstractEnvironment} available.
 * <p>Created by Jeff Gaynor<br>
 * on 4/23/12 at  4:39 PM
 */
public interface TransactionFilter {
    /**
     * Invoked after the transaction state has been determined, but before writing any response
     * @param transactionState
     * @throws Throwable
     */
public void preprocess(TransactionState transactionState) throws Throwable;

    /**
     * Invoked after the response has been written to the {@link javax.servlet.http.HttpServletResponse}
     * stream. This is the very last call made by the servlet before returning.
     * @param transactionState
     * @throws Throwable
     */
public void postprocess(TransactionState transactionState) throws Throwable;
}
