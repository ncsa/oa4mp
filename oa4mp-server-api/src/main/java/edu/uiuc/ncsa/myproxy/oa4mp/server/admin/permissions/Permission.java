package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableImpl;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/11/16 at  11:00 AM
 */
public class Permission extends IdentifiableImpl {
    public Permission(Identifier identifier) {
        super(identifier);
    }

    @Override
    public IdentifiableImpl clone() {
        Permission x = new Permission(getIdentifier());
        x.setAdminID(getAdminID());
        x.setClientID(getClientID());
        x.setApprove(isApprove());
        x.setCreate(isCreate());
        x.setDelete(isDelete());
        x.setWrite(isWrite());
        x.setRead(isRead());
        return x;
    }

    Identifier clientID;
    Identifier adminID;
    boolean read = true;
    boolean write = true;
    boolean create = true;

    public boolean isApprove() {
        return approve;
    }

    public void setApprove(boolean approve) {
        this.approve = approve;
    }


    boolean approve = true;

    public Identifier getAdminID() {
        return adminID;
    }

    public void setAdminID(Identifier adminID) {
        this.adminID = adminID;
    }

    public Identifier getClientID() {
        return clientID;
    }

    public void setClientID(Identifier clientID) {
        this.clientID = clientID;
    }

    public boolean isCreate() {
        return create;
    }

    public void setCreate(boolean create) {
        this.create = create;
    }

    public boolean isDelete() {
        return delete;
    }

    public void setDelete(boolean delete) {
        this.delete = delete;
    }

    public boolean isRead() {
        return read;
    }

    public void setRead(boolean read) {
        this.read = read;
    }

    public boolean isWrite() {
        return write;
    }

    public void setWrite(boolean write) {
        this.write = write;
    }

    boolean delete = true;

    @Override
    public String toString() {
        String out = getClass().getSimpleName() + "[";
        out = out + "permission id=" + getIdentifierString() + ",";
        out = out + "admin id=" + getAdminID() +",";
        out = out + "client id=" + getClientID() + ",";
        out = out +  (isApprove()?"a":"") + (isCreate()?"c":"") + (isDelete()?"d":"") + (isRead()?"r":"") + (isWrite()?"w":"") ;
        out = out + "]";
        return out;
    }
}
