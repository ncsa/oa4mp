package edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients;

import edu.uiuc.ncsa.security.storage.data.SerializationKeys;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/25/12 at  3:07 PM
 */
public class ClientApprovalKeys extends SerializationKeys {
    public ClientApprovalKeys() {
        identifier("oauth_consumer_key");
    }

    String approved = "approved";
    String approvalTS = "approval_ts";
    String approver = "approver";
    String status = "status";

    public String approved(String... x) {
        if (0 < x.length) approved = x[0];
        return approved;
    }

    public String status(String... x) {
        if (0 < x.length) status = x[0];
        return status;
    }

    public String approvalTS(String... x) {
        if (0 < x.length) approvalTS = x[0];
        return approvalTS;
    }

    public String approver(String... x) {
        if (0 < x.length) approver = x[0];
        return approver;
    }

    @Override
    public List<String> allKeys() {
        List<String> allKeys = super.allKeys();
        allKeys.add(approvalTS());
        allKeys.add(approved());
        allKeys.add(approver());
        allKeys.add(status());
        return allKeys;
    }
}
