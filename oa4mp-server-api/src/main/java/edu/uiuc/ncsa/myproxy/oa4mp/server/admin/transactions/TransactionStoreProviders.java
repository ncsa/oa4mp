package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions;

import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/21/16 at  10:24 AM
 */
public class TransactionStoreProviders {
    protected static DSTransactionProvider<? extends ServiceTransaction> tp;
    protected static DSTransactionKeys keys;
    protected static TransactionConverter<? extends ServiceTransaction> converter;


    public static TransactionConverter<? extends ServiceTransaction> getConverter() {
        if(converter == null){
           // converter = new TransactionConverter<OA4MPServiceTransaction>();
        }
        return converter;
    }

    public static void setConverter(TransactionConverter<? extends ServiceTransaction> converter) {
        TransactionStoreProviders.converter = converter;
    }

    public static DSTransactionKeys getKeys() {
        return keys;
    }

    public static void setKeys(DSTransactionKeys keys) {
        TransactionStoreProviders.keys = keys;
    }

    public static DSTransactionProvider<? extends ServiceTransaction> getTp() {
        return tp;
    }

    public static void setTp(DSTransactionProvider<? extends ServiceTransaction> tp) {
        TransactionStoreProviders.tp = tp;
    }


}
