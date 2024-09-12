package org.oa4mp.delegation.server.storage.uuc;

import java.util.List;

import static edu.uiuc.ncsa.security.core.util.StringUtils.RJustify;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/14/24 at  11:19 AM
 */
public class UUCResponse {

    /**
     * Total possible clients with zero or null last accessed
     */
    public int total = 0;
    /**
     * Total number of deletions attempted
     */
    public int attempted = 0;

    /**
     * The identifiers (as strings) to remove.
     */
    public List<String> found;
    /**
     * The identifiers (as strings) to archive
     */
    public List<String> archived;
    /**
     * The number skipped, i.e., that had retain = true.
     */
    public int skipped = 0;

    public ResultStats deletedStats;
    public ResultStats archivedStats;

    public String toString(boolean prettyPrint) {
        if (!prettyPrint) return toString();
        String n = prettyPrint ? "\n" : " ";
        int width = prettyPrint ? 16 : -1;
        return getClass().getSimpleName() + "{" + n +
                RJustify("archived=", width) + (archived == null ? 0 : archived.size()) + "," + n +
                RJustify("attempted=", width) + attempted + "," + n +
                RJustify("archived stats=", width) + (archivedStats == null ? "(none)" : archivedStats) + "," + n +
                RJustify("deleted stats=", width) + (deletedStats == null ? "(none)" : deletedStats) + "," + n +
                RJustify("found=", width) + (found == null ? 0 : found.size()) + "," + n +
                RJustify("retained=", width) + skipped + "," + n +
                RJustify("total=", width) + total + n +
                "}";
    }

    @Override
    public String toString() {
        return toString(false);
    }
}
