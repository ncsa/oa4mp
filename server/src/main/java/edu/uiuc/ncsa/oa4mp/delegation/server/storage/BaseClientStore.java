package edu.uiuc.ncsa.oa4mp.delegation.server.storage;

import edu.uiuc.ncsa.oa4mp.delegation.common.storage.BaseClient;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.uuc.UUCConfiguration;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/12/16 at  1:19 PM
 */
public interface BaseClientStore<V extends BaseClient> extends Store<V> {

    /**
     * Retrieve all clients of a given type from the approval store for the given status.
     *
     * @return
     */
    List<Identifier> getByStatus(String status, ClientApprovalStore clientApprovalStore);

    List<Identifier> getByApprover(String approver, ClientApprovalStore clientApprovalStore);

    /**
     * Process unused clients. This returns the total number of clients found that have
     * not access time and the number that satisfy the expiration
     */
    // Fixes https://github.com/ncsa/oa4mp/issues/80
    UUCResponse unusedClientCleanup(UUCConfiguration uucConfiguration);

    public static class UUCResponse {

        /**
         * Total possible clients with zero or null last accessed
         */
        public int total = 0;
        /**
         * Total number of deletions attempted
         */
        public int attempted = 0;
        /**
         * Actual number of successful deletes
         */
        public int success = 0;
        /**
         * It worked, but no information on why
         */
        public int no_info = 0;
        /**
         * Failed to delete outright
         */
        public int failed = 0;
        /**
         * Could not determine what happened
         */
        public int unknown = 0;
        /**
         * The identifiers (as strings) to remove.
         */
        public List<String> found;
        /**
         * The number skipped,. i.e., that had retain = true.
         */
        public int skipped = 0;

        @Override
        public String toString() {
            return toString(false);
        }

        public String toString(boolean prettyPrint) {
            return "UUCResponse{" +
                    (prettyPrint ? "\n    " : ",") + "total=" + total +
                    (prettyPrint ? ",\n    " : ",") + " attempted=" + attempted +
                    (prettyPrint ? ",\n    " : ",") + " success=" + success +
                    (prettyPrint ? ",\n    " : ",") + " no_info=" + no_info +
                    (prettyPrint ? ",\n    " : ",") + " failed=" + failed +
                    (prettyPrint ? ",\n    " : ",") + " skipped=" + skipped +
                    (prettyPrint ? ",\n    " : ",") + " unknown=" + unknown +
                    "\n}";
        }
    }


}
