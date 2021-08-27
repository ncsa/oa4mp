package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.XMLConverter;
import edu.uiuc.ncsa.security.storage.MemoryStore;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/14/20 at  10:37 AM
 */
public class TXMemoryStore<V extends TXRecord> extends MemoryStore<V> implements TXStore<V>{
    public TXMemoryStore(TXRecordProvider<V> identifiableProvider,
                         TXRecordConverter<V> converter) {
        super(identifiableProvider);
        this.converter = converter;
    }
    TXRecordConverter<V> converter;

    @Override
    public XMLConverter<V> getXMLConverter() {
        return converter;
    }

    @Override
    public MapConverter<V> getMapConverter() {
        return converter;
    }

    @Override
    public List<V> getByParentID(Identifier parentID) {
        List<V> kids = new ArrayList<>();
        for(V tx : values()){
            if(tx.parentID.equals(parentID)){
                kids.add(tx);
            }
        }
        return kids;
    }

    @Override
    public int getCountByParent(Identifier parentID) {
        return getByParentID(parentID).size();
    }
}
