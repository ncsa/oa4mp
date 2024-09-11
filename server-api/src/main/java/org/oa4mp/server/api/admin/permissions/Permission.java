package org.oa4mp.server.api.admin.permissions;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableImpl;

import java.util.List;

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

    /**
     * The chain (i.e. list) of ersatz clients. Note that this does not contain the
     * provisioning client, so if A ≻ α ≻ β ≻ γ , the A is the provisioning client
     * and the returned result is the list of ids [α, β, γ]. Note that γ is the final
     * ersatz client.
     * @return
     */
    public List<Identifier> getErsatzChain() {
        return ersatzChain;
    }

    public void setErsatzChain(List<Identifier> ersatzID) {
        this.ersatzChain = ersatzID;
    }

    List<Identifier> ersatzChain;

    public boolean hasErsatzChain(){
        return ersatzChain !=null && !ersatzChain.isEmpty();
    }
    public boolean canSubstitute() {
        return substitute;
    }

    public void setSubstitute(boolean substitute) {
        this.substitute = substitute;
    }

    boolean substitute = false;
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
