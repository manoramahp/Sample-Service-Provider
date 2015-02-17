/*
*  Copyright (c) WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*  WSO2 Inc. licenses this file to you under the Apache License,
*  Version 2.0 (the "License"); you may not use this file except
*  in compliance with the License.
*  You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations
* under the License.
*/

package org.wso2.carbon.identity.sso.agent.saml;


import org.apache.xml.security.signature.XMLSignature;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Artifact;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.core.impl.ArtifactBuilder;
import org.opensaml.saml2.core.impl.ArtifactResolveBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.xml.security.x509.X509Credential;
import org.w3c.dom.Document;
import org.wso2.carbon.identity.sso.agent.exception.SSOAgentException;
import org.wso2.carbon.identity.sso.agent.util.SSOAgentConfigs;
import org.wso2.carbon.identity.sso.agent.util.SSOAgentUtils;

import javax.net.ssl.*;
import javax.servlet.http.HttpServletRequest;
import javax.xml.soap.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.SecureRandom;
import java.security.Security;

public class ArtifactResolver {

    /**
     * Get the artifact string and include the <ArtifactResolve> in a SOAP message
     * @param request
     * @param artifact
     * @throws org.wso2.carbon.identity.sso.agent.exception.SSOAgentException
     */
    public String resolveArtifact(HttpServletRequest request, String artifact, X509Credential credential) throws SSOAgentException {

        try {
            RequestAbstractType artifactResolveMessage = buildArtifactResolve(artifact, credential);
            SOAPMessage soapRequest = createSOAPMessage(artifactResolveMessage);
            SOAPMessage soapResponse = sendSOAPMessge(soapRequest);
            return processSoapResponse(soapResponse);
        } catch (Exception e) {
            throw new SSOAgentException("Error While Resolving Artifact", e);
        }
    }

    /**
     * Build the <ArtifactResolve>
     * @param artifactString
     * @return
     */
    private ArtifactResolve buildArtifactResolve(String artifactString, X509Credential credential) throws SSOAgentException {

        // ID
        String artifactResolveRandomId = Integer.toHexString(new Double(Math.random()).intValue());

        // Issue Instance
        DateTime issueInstant = new DateTime();

        // Issuer
        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(SSOAgentConfigs.getIssuerId());

        // Artifact
        Artifact artifact = new ArtifactBuilder().buildObject();
        artifact.setArtifact(artifactString);

        // ArtifactResolve
        ArtifactResolve artifactResolve = new ArtifactResolveBuilder().buildObject();

        artifactResolve.setID(artifactResolveRandomId);
        artifactResolve.setVersion(SAMLVersion.VERSION_20);
        artifactResolve.setIssueInstant(issueInstant);
        artifactResolve.setIssuer(issuer);
        artifactResolve.setDestination(SSOAgentConfigs.getIdPArtifactResolutionUrl());
        artifactResolve.setArtifact(artifact);

        SSOAgentUtils.setSignature(artifactResolve, XMLSignature.ALGO_ID_SIGNATURE_RSA, credential);
        return artifactResolve;
    }

    /**
     * Create SOAP message
     * @param artifactResolveMessage <ArtifactResolve> to be included
     * @return
     */
    private SOAPMessage createSOAPMessage (RequestAbstractType artifactResolveMessage) throws SOAPException, IOException {

        MessageFactory messageFactory = MessageFactory.newInstance();
        SOAPMessage soapMessage = messageFactory.createMessage();
        SOAPBody soapBody = soapMessage.getSOAPBody();

        SOAPFactory soapFactory = SOAPFactory.newInstance();
        SOAPElement soapElement = soapFactory.createElement(artifactResolveMessage.getDOM());
        soapBody.addChildElement(soapElement);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        soapMessage.writeTo(baos);
        String result = baos.toString();
        return  soapMessage;
    }

    /**
     * Send SOAP Message to Artifact Resolution Service
     * @param soapRequest
     */
    private SOAPMessage sendSOAPMessge(SOAPMessage soapRequest) throws Exception {

        SOAPConnectionFactory soapConnectionFactory = SOAPConnectionFactory.newInstance();
        SOAPConnection soapConnection = soapConnectionFactory.createConnection();
        String url = SSOAgentConfigs.getIdPArtifactResolutionUrl();
        doTrustToCertificates();
        SOAPMessage soapResponse = soapConnection.call(soapRequest, url);
        soapConnection.close();
        return soapResponse;
    }

    public void doTrustToCertificates() throws Exception {
        Security.addProvider(new com.sun.net.ssl.internal.ssl.Provider());
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                        return;
                    }

                    public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                        return;
                    }
                }
        };

        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        HostnameVerifier hv = new HostnameVerifier() {
            public boolean verify(String urlHostName, SSLSession session) {
                if (!urlHostName.equalsIgnoreCase(session.getPeerHost())) {
                    System.out.println("Warning: URL host '" + urlHostName + "' is different to SSLSession host '" + session.getPeerHost() + "'.");
                }
                return true;
            }
        };
        HttpsURLConnection.setDefaultHostnameVerifier(hv);
    }


    /**
     * Process SOAP Response message
     * Authentication response or Logout response
     * @param soapResponse
     */
    private String processSoapResponse(SOAPMessage soapResponse) throws SOAPException, TransformerException {

        SOAPBody soapBody = soapResponse.getSOAPBody();
        Document doc = soapBody.extractContentAsDocument();
        Source source = new DOMSource(doc);
        StringWriter stringWriter = new StringWriter();
        Result result = new StreamResult(stringWriter);
        TransformerFactory factory = TransformerFactory.newInstance();
        Transformer transformer = factory.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        transformer.transform(source, result);
        String soapBodyStr = stringWriter.getBuffer().toString();
        return soapBodyStr;
    }

}