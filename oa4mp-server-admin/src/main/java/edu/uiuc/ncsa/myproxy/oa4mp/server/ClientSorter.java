package edu.uiuc.ncsa.myproxy.oa4mp.server;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.util.Iso8601;
import edu.uiuc.ncsa.security.delegation.storage.BaseClient;
import edu.uiuc.ncsa.security.util.cli.BasicSorter;

import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/22/14 at  10:22 AM
 */
public class ClientSorter extends BasicSorter {
    public static final String ID_SORT_SWITCH = "i";
    public static final String DATE_SORT_SWITCH = "d";

    protected boolean sortOnIds = false;

    protected boolean sortOnDates = true;

    protected ArrayList<Identifiable> sortByDate(List<Identifiable> arg) {
        TreeMap<String, ArrayList<Identifiable>> tm = new TreeMap<>();
         // At issue is that dates are not always unique (e.g. if the backing store is a database
        // and is restored from a backup, the creation timestamps may be set to the same value). This
        // allows for multiple values for each key and then returns everything.
        for (int i = 0; i < arg.size(); i++) {
            BaseClient client = (BaseClient) arg.get(i);
            String key = Iso8601.date2String(client.getCreationTS());
            if(tm.containsKey(key)){
                       tm.get(key).add(client);
            }else{
               ArrayList<Identifiable> x = new ArrayList<>();
                x.add(client);
                tm.put(key, x);
            }
        }
        // now we have to unpack any lists.
        ArrayList<Identifiable> outList = new ArrayList<>();
        for(String key : tm.keySet()){
            outList.addAll(tm.get(key));
        }
        return outList;

    }

    protected ArrayList<Identifiable> sortByID(List<Identifiable> arg) {
        TreeMap<String, Identifiable> tm = new TreeMap<>();

        for (int i = 0; i < arg.size(); i++) {
            BaseClient client = (BaseClient) arg.get(i);
            tm.put(client.getIdentifierString(), client);
        }
        return new ArrayList(tm.values());

    }

    @Override
    public ArrayList<Identifiable> sort(List<Identifiable> arg) {
        // Fix CIL-378: Clients with same creation timestamp are not all displayed in CLI.
        if (sortOnIds) {
            return sortByID(arg);
        }

        if(sortOnDates){
            return sortByDate(arg);
        }
        return new ArrayList();
    }

    @Override
    public void setState(String args) {
        if (!args.startsWith("-")) return;
        if (args.contains(ID_SORT_SWITCH)) {
            sortOnIds = true;
            sortOnDates = false;
            return;
        }
        if (args.contains(DATE_SORT_SWITCH)) {
            sortOnIds = false;
            sortOnDates = true;
            return;

        }
    }
}
