package org.oa4mp.server.loader.qdl.scripting;

import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.storage.transactions.OA2ServiceTransaction;
import org.oa4mp.server.loader.oauth2.storage.tx.TXRecord;
import org.oa4mp.server.loader.oauth2.loader.OA2ConfigurationLoader;
import org.oa4mp.server.loader.qdl.QDLXMLConstants;
import org.qdl_lang.evaluate.MetaEvaluator;
import org.qdl_lang.evaluate.OpEvaluator;
import org.qdl_lang.functions.FStack;
import org.qdl_lang.module.MIStack;
import org.qdl_lang.module.MTStack;
import org.qdl_lang.state.State;
import org.qdl_lang.variables.QDLStem;
import org.qdl_lang.variables.VStack;
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
    public OA2State(
            VStack vStack,
            OpEvaluator opEvaluator,
            MetaEvaluator metaEvaluator,
            FStack ft,
            MTStack mTemplates,
            MIStack mInstance,
            MyLoggingFacade myLoggingFacade,
            boolean isServerMode,
            boolean isRestrictedIO,
            boolean assertionsOn,
            boolean strictACLs,
            JSONWebKeys keys) {
        super(vStack, opEvaluator, metaEvaluator,
                ft, mTemplates, mInstance, myLoggingFacade, isServerMode, isRestrictedIO, assertionsOn);
        this.strictACLs = strictACLs;
        this.jsonWebKeys = keys;
    }

    @Override
    public State newLocalState() {
        OA2State oa2State = (OA2State) super.newLocalState();
        return oa2StateInit(oa2State);
    }

    private OA2State oa2StateInit(OA2State oa2State) {
        oa2State.setOa2se(getOa2se());
        oa2State.setTransaction(getTransaction());
        oa2State.setStrictACLs(isStrictACLs());
        oa2State.setJsonWebKeys(getJsonWebKeys());
        oa2State.setTxRecord(getTxRecord());
        oa2State.setAclList(getAclList());
        oa2State.setAclBlackList(getAclBlackList());
        oa2State.setRequest(getRequest());
        return oa2State;
    }

    @Override
    public State newFunctionState() {
        OA2State oa2State = (OA2State) super.newFunctionState();
        return oa2StateInit(oa2State);
    }

    @Override
    public State newCleanState() {
        // Note that clean state refers to the QDL state -- the OA2 service environment does not change!
        OA2State oa2State = (OA2State) super.newCleanState();
        return oa2StateInit(oa2State);
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
     * {@link OA2ConfigurationLoader#STRICT_ACLS} attribute of the qdl tag) will
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

    transient List<Identifier> aclList = new ArrayList<>();

    public List<Identifier> getAclBlackList() {
        return aclBlackList;
    }

    public void setAclBlackList(List<Identifier> aclBlackList) {
        this.aclBlackList = aclBlackList;
    }

    transient List<Identifier> aclBlackList = new ArrayList<>();

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
        if (txRecord != null) {
            txRecord.toXML(xsw);
        }
    }

    @Override
    public State newInstance(
            VStack vStack,
            OpEvaluator opEvaluator,
            MetaEvaluator metaEvaluator,
            FStack fStack,
            MTStack mTemplates,
            MIStack mInstances,
            MyLoggingFacade myLoggingFacade,
            boolean isServerMode,
            boolean isRestrictedIO,
            boolean assertionsOn) {
        return new OA2State(
                vStack,
                opEvaluator,
                metaEvaluator,
                fStack,
                mTemplates,
                mInstances,
                myLoggingFacade,
                isServerMode,
                isRestrictedIO,
                assertionsOn,
                isStrictACLs(),
                getJsonWebKeys());
    }

    @Override
    protected QDLStem addManifestConstants(String path) {
        return super.addManifestConstants(path);
    }
}
