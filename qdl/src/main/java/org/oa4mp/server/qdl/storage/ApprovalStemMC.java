package org.oa4mp.server.qdl.storage;

import org.oa4mp.delegation.common.storage.clients.ClientApprovalKeys;
import org.oa4mp.delegation.server.storage.ClientApproval;
import org.qdl_lang.variables.QDLStem;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import static org.qdl_lang.variables.StemUtility.put;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/21/20 at  6:11 AM
 */
public class ApprovalStemMC<V extends ClientApproval> extends StemConverter<V> {
    public ApprovalStemMC(MapConverter<V> mapConverter) {
        super(mapConverter);
    }

    ClientApprovalKeys kk() {
        return (ClientApprovalKeys) keys;
    }
    /*
      4 attributes
    String approved = "approved";
    String approvalTS = "approval_ts";
    String approver = "approver";
    String status = "status";
     */

    @Override
    public V fromMap(QDLStem stem, V v) {
        v = super.fromMap(stem, v);
        if (stem.containsKey(kk().approved())) {
            v.setApproved(stem.getBoolean(kk().approved()));
        }
        if (isTimeOk(stem, kk().approvalTS())) {
            v.setApprovalTimestamp(toDate(stem, kk().approvalTS()));
        }
        if (isStringKeyOK(stem, kk().status())) {
            ClientApproval.Status status1 = ClientApproval.Status.resolveByStatusValue(stem.getString(kk().status()));
            v.setStatus(status1);
        } else {
            v.setStatus(ClientApproval.Status.NONE);
        }
        if (isStringKeyOK(stem, kk().approver())) {
            v.setApprover(stem.getString(kk().approver()));
        }
        return v;
    }

    @Override
    public QDLStem toMap(V v, QDLStem stem) {
       stem =  super.toMap(v, stem);

        if (v.getStatus() == null) {
            put(stem,kk().status(), ClientApproval.Status.NONE.getStatus());
        } else {
            put(stem,kk().status(), v.getStatus().getStatus());
        }
        if(v.getApprovalTimestamp() != null) {
            put(stem, kk().approvalTS(), v.getApprovalTimestamp().getTime());
        }
        if (!StringUtils.isTrivial(v.getApprover())) {
            put(stem,kk().approver(), v.getApprover());
        }
        put(stem, kk().approved(), v.isApproved());
        return stem;
    }
}
