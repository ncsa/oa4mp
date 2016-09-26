package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.table.DSTransactionTable;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;

import java.sql.Types;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/28/14 at  5:24 PM
 */
public class OA2TransactionTable extends DSTransactionTable {
    public OA2TransactionTable(OA2TransactionKeys keys, String schema, String tablenamePrefix, String tablename) {
        super(keys, schema, tablenamePrefix, tablename);
    }

    protected OA2TransactionKeys getOA2Keys(){
        return (OA2TransactionKeys) keys;
    }


    @Override
    public void createColumnDescriptors() {
        super.createColumnDescriptors();
        getColumnDescriptor().add(new ColumnDescriptorEntry(getOA2Keys().refreshToken(), java.sql.Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getOA2Keys().refreshTokenValid(), Types.BOOLEAN));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getOA2Keys().expiresIn(), Types.BIGINT));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getOA2Keys().nonce(), Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getOA2Keys().authTime(), Types.TIMESTAMP));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getOA2Keys().scopes(), Types.LONGVARCHAR));
    }

    public String getByRefreshTokenStatement() {
           return "SELECT * FROM " + getFQTablename() + " WHERE " + getOA2Keys().refreshToken() + "=?";
       }
    public String getByUsernameStatement() {
           return "SELECT * FROM " + getFQTablename() + " WHERE " + getOA2Keys().username() + "=?";
       }

}
