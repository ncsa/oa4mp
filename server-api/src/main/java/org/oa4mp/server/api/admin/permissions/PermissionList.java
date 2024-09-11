package org.oa4mp.server.api.admin.permissions;

import java.util.LinkedList;

/**
 * For use with multiple permissions, e.g., all the permissions granted to a client
 * by an admin.
 * <p>Created by Jeff Gaynor<br>
 * on 11/23/16 at  2:59 PM
 */
public class PermissionList extends LinkedList<Permission> {
    public void canApprove(){
        boolean canApprove = false;
        for(Permission p : this){
              canApprove = canApprove || p.isApprove();
        }

        if(!canApprove) throw new PermissionException("approving not permitted");
    }

    public void canRead(){
        boolean canRead = false;
        for(Permission p : this){
              canRead = canRead || p.isRead();
        }

        if(!canRead) throw new PermissionException("read not permitted");
    }

    public void canWrite(){
        boolean canWrite = false;
        for(Permission p : this){
              canWrite = canWrite || p.isWrite();
        }

        if(!canWrite) throw new PermissionException("write not permitted");
    }

    public void canCreate(){
        boolean canCreate = false;
        for(Permission p : this){
              canCreate = canCreate || p.isCreate();
        }

        if(!canCreate) throw new PermissionException("create not permitted");
    }

    public void canDelete(){
        boolean canDelete = false;
        for(Permission p : this){
              canDelete = canDelete || p.isDelete();
        }
        if(!canDelete) throw new PermissionException("Cannot delete");
    }
    
    public void canSubstitute(){
           boolean canSubstitute = false;
           for(Permission p : this){
               canSubstitute = canSubstitute || p.canSubstitute();
           }

           if(!canSubstitute) throw new PermissionException("Cannot substitute");
       }
}
