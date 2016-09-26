package edu.uiuc.ncsa.myproxy.oa4mp.server;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.util.Iso8601;
import edu.uiuc.ncsa.security.delegation.storage.Client;
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

    @Override
    public ArrayList<Identifiable> sort(List<Identifiable> arg) {
        TreeMap<String, Identifiable> tm = new TreeMap<>();

        for (int i = 0; i < arg.size(); i++) {
            Client client = (Client) arg.get(i);
            if (sortOnDates) {
                tm.put(Iso8601.date2String(client.getCreationTS()), client);
            } else if (sortOnIds) {
                tm.put(client.getIdentifierString(), client);
            }
        }
        return new ArrayList(tm.values());
    }

    @Override
    public void setState(String args) {
        if(!args.startsWith("-")) return;
        if(args.contains(ID_SORT_SWITCH)){
            sortOnIds = true;
            sortOnDates = false;
            return;
        }
        if(args.contains(DATE_SORT_SWITCH)){
            sortOnIds = false;
            sortOnDates = true;
            return;

        }
    }
}
