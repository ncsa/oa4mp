package org.oa4mp.delegation.server.storage.uuc;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/14/24 at  11:21 AM
 */
public class ResultStats {
    /**
     * Actual number of successful deletes
     */
    public int success = 0;
    /**
     * It worked, but no information on why
     */
    public int noInfo = 0;
    /**
     * Failed to delete outright
     */
    public int failed = 0;
    /**
     * Could not determine what happened
     */
    public int unknown = 0;

    public ResultStats(int success, int noInfo, int failed, int unknown) {
        this.success = success;
        this.noInfo = noInfo;
        this.failed = failed;
        this.unknown = unknown;
    }

    @Override
    public String toString() {
        return "ResultStats{" +
                "success=" + success +
                ", noInfo=" + noInfo +
                ", failed=" + failed +
                ", unknown=" + unknown +
                '}';
    }
}
