package edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXRecord;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.QDLXMLConstants;
import edu.uiuc.ncsa.qdl.evaluate.MetaEvaluator;
import edu.uiuc.ncsa.qdl.evaluate.OpEvaluator;
import edu.uiuc.ncsa.qdl.functions.FTStack;
import edu.uiuc.ncsa.qdl.module.MAliases;
import edu.uiuc.ncsa.qdl.module.MTemplates;
import edu.uiuc.ncsa.qdl.state.State;
import edu.uiuc.ncsa.qdl.state.SymbolStack;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;

import javax.servlet.http.HttpServletRequest;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.stream.events.XMLEvent;
import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/9/20 at  4:45 PM
 */
public class OA2State extends State {
    public OA2State(MAliases mAliases,
                    SymbolStack symbolStack,
                    OpEvaluator opEvaluator,
                    MetaEvaluator metaEvaluator,
                    FTStack ft,
                    MTemplates mTemplates,
                    MyLoggingFacade myLoggingFacade,
                    boolean isServerMode,
                    boolean isRestrictedIO,
                    boolean assertionsOn,
                    boolean strictACLs,
                    JSONWebKeys keys) {
        super(mAliases, symbolStack, opEvaluator, metaEvaluator,
                ft, mTemplates, myLoggingFacade, isServerMode, isRestrictedIO, assertionsOn);
        this.strictACLs = strictACLs;
        this.jsonWebKeys = keys;
    }

    transient OA2ServiceTransaction transaction;
    transient OA2SE oa2se;
    transient HttpServletRequest request;

    public JSONWebKeys getJsonWebKeys() {
        return jsonWebKeys;
    }

    public void setJsonWebKeys(JSONWebKeys jsonWebKeys) {
        this.jsonWebKeys = jsonWebKeys;
    }

    JSONWebKeys jsonWebKeys;
    public void setStrictACLs(boolean strictACLs) {
        this.strictACLs = strictACLs;
    }

    /**
     * If ACLs are enforced strictly. Strictly means that no access control list is ok, connoting general access.
     * Strict ACLs means there must be an exact match of one of the identifiers.
     * <br/><br/>
     * Setting this true in the configuration (with the
     * {@link edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader#STRICT_ACLS} attribute of the qdl tag) will
     * lock down the server so that nothing can execute unless everything is granted explicit permission. Use this wisely.
     *
     * @return
     */
    public boolean isStrictACLs() {
        return strictACLs;
    }

    boolean strictACLs = false;

    public List<Identifier> getAclList() {
        return aclList;
    }

    public void setAclList(List<Identifier> aclList) {
        this.aclList = aclList;
    }

    transient List<Identifier> aclList =new ArrayList<>();

    public List<Identifier> getAclBlackList() {
        return aclBlackList;
    }

    public void setAclBlackList(List<Identifier> aclBlackList) {
        this.aclBlackList = aclBlackList;
    }

    transient List<Identifier> aclBlackList =new ArrayList<>();

    public TXRecord getTxRecord() {
        return txRecord;
    }

    public void setTxRecord(TXRecord txRecord) {
        this.txRecord = txRecord;
    }

    transient TXRecord txRecord;

    public OA2ServiceTransaction getTransaction() {
        return transaction;
    }

    public void setTransaction(OA2ServiceTransaction transaction) {
        this.transaction = transaction;
    }

    public OA2SE getOa2se() {
        return oa2se;
    }

    public void setOa2se(OA2SE oa2se) {
        this.oa2se = oa2se;
    }

    public HttpServletRequest getRequest() {
        return request;
    }

    public void setRequest(HttpServletRequest request) {
        this.request = request;
    }

    public List<Identifier> getAdminIDs() {
        return getOa2se().getPermissionStore().getAdmins(getClientID());
    }

    public Identifier getClientID() {
        return getTransaction().getClient().getIdentifier();
    }

    @Override
    public void readExtraXMLElements(XMLEvent xe, XMLEventReader xer) throws XMLStreamException {
        super.readExtraXMLElements(xe, xer);
        switch (xe.asStartElement().getName().getLocalPart()) {
            case QDLXMLConstants.TX_RECORD:
                txRecord = new TXRecord(null);
                txRecord.fromXML(xer);
                break;

        }
    }

    @Override
    public void writeExtraXMLElements(XMLStreamWriter xsw) throws XMLStreamException {
        super.writeExtraXMLElements(xsw);
        if(txRecord != null){
            txRecord.toXML(xsw);
        }
    }

    @Override
    public State newInstance(MAliases mAliases,
                             SymbolStack symbolStack,
                             OpEvaluator opEvaluator,
                             MetaEvaluator metaEvaluator,
                             FTStack ftStack,
                             MTemplates mTemplates,
                             MyLoggingFacade myLoggingFacade,
                             boolean isServerMode,
                             boolean isRestrictedIO,
                             boolean assertionsOn) {
        return new OA2State(mAliases,
                symbolStack,
                opEvaluator,
                metaEvaluator,
                ftStack,
                mTemplates,
                myLoggingFacade,
                isServerMode,
                isRestrictedIO,
                assertionsOn,
                isStrictACLs(),
                getJsonWebKeys());
    }
}
