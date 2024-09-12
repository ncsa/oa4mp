package org.oa4mp.delegation.server.storage;

import edu.uiuc.ncsa.security.core.DateComparable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableImpl;
import edu.uiuc.ncsa.security.core.util.StatusValue;

import java.util.Date;

/**
 * A client approval. Note that this has the same id as the client record! Changing the identifier will
 * effectively remove this approval.
 * <p>Created by Jeff Gaynor<br>
 * on May 26, 2011 at  9:40:02 AM
 */
public class ClientApproval extends IdentifiableImpl implements DateComparable {

    public ClientApproval(Identifier identifier) {
        super(identifier);
    }

    static final long serialVersionUID = 1714880068599897702L;
    boolean approved;
    String approver;
    Date approvalTimestamp;

    @Override
    public Date getCreationTS() {
        return getApprovalTimestamp();
    }

    /**
     * This status enum has values that the elements assume. This is to control their actual internal values so that
     * for instance, if the name changes, the associated value remains constant (which allows for much easier backwards
     * compatibility in the future.)
     */

    public enum Status implements StatusValue {
        NONE("none"),
        DENIED("denied"),
        APPROVED("approved"),
        REVOKED("revoked"),
        TEMPLATE("template"), // not really used.
        PENDING("pending");

        private final String status;

        private Status(String status) {
            this.status = status;
        }

        public String getStatus() {
            return status;
        }

        public static Status resolveByStatusValue(String code) {
            Status[] enumConstants = Status.class.getEnumConstants();
            for (Status entry : enumConstants) {
                if (entry.getStatus().equals(code)) return entry;
            }
            // no such value ==> return a null.
            return null;
        }
    }

    Status status = Status.NONE;

    public Status getStatus() {
        return status;
    }

    public void setStatus(Status status) {
        this.status = status;
    }

    public Date getApprovalTimestamp() {
        return approvalTimestamp;
    }

    public void setApprovalTimestamp(Date approvalTimestamp) {
        this.approvalTimestamp = approvalTimestamp;
    }

    public boolean isApproved() {
        return approved;
    }

    public void setApproved(boolean approved) {
        boolean oldValue = approved;
        this.approved = approved;
        if (approved) {
            setStatus(Status.APPROVED);
        } else {
            if (oldValue) {
                setStatus(Status.REVOKED);
            }
        }
    }

    public String getApprover() {
        return approver;
    }

    public void setApprover(String approver) {
        this.approver = approver;
    }


    @Override
    public boolean equals(Object obj) {
        if (!super.equals(obj)) return false;
        if (!(obj instanceof ClientApproval)) return false;
        ClientApproval ca = (ClientApproval) obj;
        if (!getIdentifierString().equals(ca.getIdentifierString())) return false;
        if (!(isApproved() == ca.isApproved())) return false;
        if (getApprover() == null && ca.getApprover() == null) return true;
        if (getApprover() != null && ca.getApprover() == null) return false;
        if (getApprover() == null && ca.getApprover() != null) return false;
        if (!getApprover().equals(ca.getApprover())) return false;
        return true;
    }

    @Override
    public IdentifiableImpl clone() {
        ClientApproval ca = new ClientApproval(getIdentifier());
        ca.setApprover(getApprover());
        ca.setStatus(getStatus());
        ca.setApprovalTimestamp(getApprovalTimestamp());
        ca.setApproved(isApproved());
        return ca;
    }

    @Override
    public String toString() {
        String x = getClass().getSimpleName() + "[approved=" + isApproved() + ", status=" + status +
                ", approver=" + getApprover() + ", id=" + getIdentifierString() + ", on " + getApprovalTimestamp() + "]";
        return x;
    }


}
