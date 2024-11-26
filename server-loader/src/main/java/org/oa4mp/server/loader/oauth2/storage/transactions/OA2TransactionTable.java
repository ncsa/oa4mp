package org.oa4mp.server.loader.oauth2.storage.transactions;

import org.oa4mp.server.api.admin.transactions.DSTransactionTable;
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
        getColumnDescriptor().add(new ColumnDescriptorEntry(getOA2Keys().atJWT(), Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getOA2Keys().authTime(), Types.TIMESTAMP));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getOA2Keys().authzGrantLifetime(), Types.BIGINT));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getOA2Keys().expiresIn(), Types.BIGINT));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getOA2Keys().idTokenIdentifier(), Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getOA2Keys().idTokenLifetime(), Types.BIGINT));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getOA2Keys().isRFC8628(), Types.BOOLEAN));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getOA2Keys().nonce(), Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getOA2Keys().proxyID(), Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getOA2Keys().refreshToken(), java.sql.Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getOA2Keys().refreshTokenExpiresAt(), Types.BIGINT));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getOA2Keys().refreshTokenLifetime(), Types.BIGINT));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getOA2Keys().refreshTokenValid(), Types.BOOLEAN));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getOA2Keys().reqState(), Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getOA2Keys().rtJWT(), Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getOA2Keys().scopes(), Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getOA2Keys().states(), Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getOA2Keys().userCode(), Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getOA2Keys().validatedScopes(), Types.LONGVARCHAR));
    }

    public String getByRefreshTokenStatement() {
           return "SELECT * FROM " + getFQTablename() + " WHERE " + getOA2Keys().refreshToken() + "=?";
       }
    public String getByUsernameStatement() {
           return "SELECT * FROM " + getFQTablename() + " WHERE " + getOA2Keys().username() + "=?";
       }

    public String getByClientIDStatement() {
        return "SELECT " + getOA2Keys().identifier() + " FROM " + getFQTablename() + " WHERE " + getOA2Keys().clientKey() + "=?";
    }


    /**
     * Get all of the client IDs in the table for some statisitics
     * @return
     */
    public String getAllClientIDsStatement() {
        return "SELECT " + getOA2Keys().clientKey() + " FROM " + getFQTablename();
    }

    public String getTokenInfoStatement() {
           return "SELECT " +
                   getOA2Keys().identifier() + ", " +
                   getOA2Keys().atJWT() + ", " +
                   getOA2Keys().rtJWT() + ", " +
                   getOA2Keys().clientKey() + ", " +
                   getOA2Keys().accessToken() + ", " +
                   getOA2Keys().accessTokenValid() + ", " +
                   getOA2Keys().expiresIn() + ", " +
                   getOA2Keys().refreshToken() + ", " +
                   getOA2Keys().refreshTokenValid() + ", " +
                   getOA2Keys().refreshTokenLifetime() + 
                   " FROM " + getFQTablename() + " WHERE " + getOA2Keys().username() + "=?";
       }
    public String getRFC8628() {
           return "SELECT " + getOA2Keys().states() + " FROM " + getFQTablename() + " WHERE " + getOA2Keys().isRFC8628() + "= true";
       }

    public String getByUserCode() {
           return "SELECT * FROM " + getFQTablename() + " WHERE " + getOA2Keys().userCode() + "= ?";
       }
       public String CheckUserCodeExists(){
        // select exists(select * from client_approvals where client_id = 'oa4mp:/client_id/5d94fb8d63353ff70b2506611ef0685');
           return "select exists(select * from " + getFQTablename() + " WHERE " + getOA2Keys().userCode() + "= ?)";
       }

    public String getByProxyID() {
           return "SELECT * FROM " + getFQTablename() + " WHERE " + getOA2Keys().proxyID() + "= ?";
       }

    public String getByAccessTokenAndClientStatement() {
           return "SELECT * FROM " + getFQTablename() + " WHERE " + getOA2Keys().accessToken() + "=? AND " + getOA2Keys().clientKey() + "=?";
       }
    public String getByRefreshTokenAndClientStatement() {
           return "SELECT * FROM " + getFQTablename() + " WHERE " + getOA2Keys().refreshToken() + "=? AND " + getOA2Keys().clientKey() + "=?";
       }
    // https://github.com/ncsa/oa4mp/issues/128
    public String getByIDTokenID() {
              return "SELECT * FROM " + getFQTablename() + " WHERE " + getOA2Keys().idTokenIdentifier() + "= ?";
          }

}
