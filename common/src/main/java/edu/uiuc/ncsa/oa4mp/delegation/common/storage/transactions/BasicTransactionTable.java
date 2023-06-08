package edu.uiuc.ncsa.oa4mp.delegation.common.storage.transactions;

import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import static java.sql.Types.LONGVARCHAR;

/**
 * Models and SQL table that holds transactions.
 * <p>Created by Jeff Gaynor<br>
 * on May 10, 2010 at  10:44:32 AM
 */
abstract public class BasicTransactionTable extends Table {
    /**
     * The schema and prefix are not part of the table's information, actually, but are needed to
     * create its fully qualified name in context. Hence they must be supplied.
     *
     * @param schema
     * @param tablenamePrefix
     */
    public BasicTransactionTable(BasicTransactionKeys keys,
                                 String schema,
                                 String tablenamePrefix,
                                 String tablename) {
        super(keys, schema, tablenamePrefix, tablename);
    }


    protected BasicTransactionKeys btk(){return (BasicTransactionKeys)keys;}
    @Override
    public void createColumnDescriptors() {
        getColumnDescriptor().add(new ColumnDescriptorEntry(btk().tempCred(), LONGVARCHAR, false, true));
        getColumnDescriptor().add(new ColumnDescriptorEntry(btk().authGrant(), LONGVARCHAR, true, false));
        getColumnDescriptor().add(new ColumnDescriptorEntry(btk().accessToken(), LONGVARCHAR, true, false));
        getColumnDescriptor().add(new ColumnDescriptorEntry(btk().verifier(), LONGVARCHAR, true, false));

    }

    public String getByTempCredStatement() {
        return "SELECT * FROM " + getFQTablename() + " WHERE " + btk().tempCred() + "=?";
    }

    public String getByAccessTokenStatement() {
        return "SELECT * FROM " + getFQTablename() + " WHERE " + btk().accessToken() + "=?";
    }


    public String getByVerifierStatement() {
        return "SELECT * FROM " + getFQTablename() + " WHERE " + btk().verifier() + "=?";
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[schema=" + getSchema() + ", prefix=" + getTablenamePrefix() + ", name=" + getFQTablename() + "]";
    }
}
