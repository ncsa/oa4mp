package edu.uiuc.ncsa.oa4mp.delegation.client;

import edu.uiuc.ncsa.oa4mp.delegation.client.request.*;
import edu.uiuc.ncsa.oa4mp.delegation.client.server.AGServer;
import edu.uiuc.ncsa.oa4mp.delegation.client.server.ATServer;
import edu.uiuc.ncsa.oa4mp.delegation.client.server.PAServer;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.Request;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.Response;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.Server;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.Client;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AuthorizationGrant;

import java.net.URI;
import java.util.Map;

/**
 * <B>THE</B> service API. This is a facade for the various bits of delegation a client needs
 * to get a protected asset (mostly we are interested in certificates).
 * The underlying messages might mutate, but the overall patterns do not vary much at all.
 * This abstraction layer keeps those patterns and shoves everything that is implementation
 * specific into separate modules. The nomenclature used throughout is OAuth 2.0:
 * <ul>
 * <li>Asset = the thing that is being delegated. Here usually it is a certificate.</li>
 * <li>Client = the application requesting delegation</li>
 * <li>Resource Owner = The person (or maybe thing) who owns the asset </li>
 * <li>Authorization Server = The server that authorizes access to asset</li>
 * <li>Resource Server = The server that actually has the asset</li>
 * </ul>
 * Note that asset, protected asset and resource are all pretty much used interchangeably.<br><br>
 * The steps then are as follows.
 * <ol>
 * <li>A resource owner tells a client to use a protected resource</li>
 * <li>The client starts the request cycle. It gets an authorization grant and a uri pointing it to the authorization server.</li>
 * <li>The owner grants authorization.</li>
 * <li>The authorization server notifies the client via a callback, getting the authorization grant (which identifies the transaction)
 * and a verifier showing resource owner approval.</li>
 * <li>The client requests the asset using the grant and verifier.</li>
 * </ol>
 * This is based on OAuth and it does the complete, specification compliant exchanges. However, since we have a
 * few special cases which vastly streamline this, only a very simple API is really what a client needs.
 * <p>Generally applications will
 * write to this to get their functionality and only in exceptional cases will
 * use the implementations of the underlying service. Direct references to protocols (e.g. OAuth 1.0a)
 * are inherently fragile and will break at some point, e.g. when trying to use OAuth 2.0. One of the strongest
 * arguments for doing it this way is that services may have to support several types of requests (OAuth 1 and 2)
 * and this design allows for keeping multiple instances cleanly separated.
 * <p>Created by Jeff Gaynor<br>
 * on Apr 4, 2011 at  3:51:41 PM
 */
public abstract class DelegationService implements Server {
    protected DelegationService(AGServer agServer,
                                ATServer atServer,
                                PAServer paServer
    ) {

        this.agServer = agServer;
        this.atServer = atServer;
        this.paServer = paServer;
    }

    /**
     * Starts the delegation process. This requests that the server permit delegation.
     *
     * @return
     */
    public DelegationResponse processDelegationRequest(DelegationRequest delegationRequest) {
        AGRequest agReq = new AGRequest();
        agReq.setClient(delegationRequest.getClient());
        agReq.setParameters(delegationRequest.getParameters());
        AGResponse agResp = (AGResponse) getAgServer().process(agReq);
        DelegationResponse delResp = new DelegationResponse(agResp.getAuthorizationGrant());
        delResp.setRedirectUri(createRedirectURL(delegationRequest, agResp));
        return delResp;
    }

    protected ATResponse getAT(AuthorizationGrant grant, Client client, Map<String, String> parameters) {
        return getAT(grant, client, parameters);
    }

    protected ATResponse getAT(ATRequest atRequest){
        ATResponse atresp = (ATResponse) getAtServer().process(atRequest);
        return atresp;
    }

    public ATResponse getAT(DelegatedAssetRequest delegationAssetRequest) {
        return getAT(new ATRequest(delegationAssetRequest));
    }

    /**
     * Gets the asset once the delegation has been approved. This will typically involve getting tokens as
     * needed from the authorization server then accessing the resource server, so this actually does two
     * legs in the protocol in quick succession. If you need to do these separately, then invoke
     * them as <br><br>
     * getAT<br>
     * getCert<br><br>
     * with the correct parameters.
     *
     * @return
     */
    public DelegatedAssetResponse processAssetRequest(DelegatedAssetRequest delegationAssetRequest) {
        // First step is to get the access token
        ATResponse atResp = getAT(delegationAssetRequest);
        // Then get the cert
        return getCert(atResp, delegationAssetRequest.getClient(), delegationAssetRequest.getAssetParameters());

    }

    public DelegatedAssetResponse getCert(ATResponse atResponse, Client client, Map<String, String> assetParameters) {
        PARequest paReq = new PARequest();
        paReq.setClient(client);
        paReq.setAccessToken(atResponse.getAccessToken());
        paReq.setParameters(assetParameters);
        PAResponse paResp = (PAResponse) getPaServer().process(paReq);
        DelegatedAssetResponse dap = new DelegatedAssetResponse(paResp.getProtectedAsset());
        dap.setAdditionalInformation(paResp.getAdditionalInformation());
        return dap;

    }

    public abstract URI createRedirectURL(DelegationRequest delegationAssetRequest, AGResponse agResp);

    public Response process(Request request) {
        return request.process(this);
    }

    /**
     * The authorization server. This server issues access tokens.
     *
     * @return
     */
    public ATServer getAtServer() {
        return atServer;
    }


    /**
     * The resource server. This server hosts the protected assets.
     *
     * @return
     */
    public PAServer getPaServer() {
        return paServer;
    }


    ATServer atServer;

    /**
     * This server issues the authorization grant that starts the delegation process.
     *
     * @return
     */
    public AGServer getAgServer() {
        return agServer;
    }


    AGServer agServer;
    PAServer paServer;


}
