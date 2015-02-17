package saml;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.ArtifactResponse;
import org.wso2.carbon.identity.sso.agent.exception.SSOAgentException;
import org.wso2.carbon.identity.sso.agent.saml.ArtifactBindingImpl;
import org.wso2.carbon.identity.sso.agent.saml.SAML2SSOManager;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.StringReader;

public class ArtifactResolutionService {

    public OMElement resolveArtifact(OMElement omElement) throws XMLStreamException, SSOAgentException {

        String xmlString = omElement.toString();
        ArtifactResolve artifactResolve = (ArtifactResolve)SAML2SSOManager.unmarshall(xmlString);

        ArtifactResponse artifactResponse = ArtifactBindingImpl.getInstance().buildArtifactResponse(artifactResolve);
        String xml = SAML2SSOManager.marshall(artifactResponse);

        XMLStreamReader reader = XMLInputFactory.newInstance().createXMLStreamReader(new StringReader(xml));
        StAXOMBuilder builder = new StAXOMBuilder(reader);
        return builder.getDocumentElement();
    }

}
