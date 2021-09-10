package org.gluu.idp.externalauth;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.gluu.util.StringHelper;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.AuthenticationResult;
import net.shibboleth.idp.authn.context.AuthenticationContext;

public class FilterFlowsByAcrChangedAuthn extends AbstractAuthenticationAction {

	private static final String OX_AUTH_FLOW_ID = "authn/oxAuth";
	private final Logger LOG = LoggerFactory.getLogger(FilterFlowsByAcrChangedAuthn.class);

	public FilterFlowsByAcrChangedAuthn() {
	}

	protected boolean doPreExecute(ProfileRequestContext profileRequestContext,
			AuthenticationContext authenticationContext) {
		if (!super.doPreExecute(profileRequestContext, authenticationContext)) {
			return false;
		}
		
		Map<String, AuthenticationResult> activeResultsMap = authenticationContext.getActiveResults();
		if (!activeResultsMap.containsKey(OX_AUTH_FLOW_ID)) {
			LOG.debug("{} Session does not have authn/oxAuth results, nothing to do", getLogPrefix());
			return false;
		}

		AuthenticationResult authenticationResult = authenticationContext.getActiveResults().get(OX_AUTH_FLOW_ID);
		String usedAcr = authenticationResult.getAdditionalData().get(ShibOxAuthAuthServlet.OXAUTH_ACR_USED);

		List<String> requestedAcrs = determineAcrs(profileRequestContext);
		
		String requestedAcr = null;
		if ((requestedAcrs != null) && (requestedAcrs.size() > 0)) {
			requestedAcr = requestedAcrs.get(0);
		}

		LOG.trace("{} Used ACR: {}, requested ACR: {}", getLogPrefix(), usedAcr, requestedAcr);

		if (StringHelper.equals(usedAcr, requestedAcr)) {
			LOG.debug("{} Used and requested ACR is the same: {}, nothing to do", getLogPrefix(), usedAcr);
			return false;
		}

		LOG.debug("{} Force to create new AuthZ request with new ACR: {}, nothing to do", getLogPrefix(), requestedAcr);
		return true;
	}
	
	protected List<String> determineAcrs(ProfileRequestContext profileRequestContext) {
        AuthnRequest authnRequest = (AuthnRequest) profileRequestContext.getInboundMessageContext().getMessage();
        if (authnRequest != null) {
            RequestedAuthnContext authnContext = authnRequest.getRequestedAuthnContext();
            if (authnContext != null) {
                List<String> acrs = authnContext.getAuthnContextClassRefs().stream()
                    .map(AuthnContextClassRef::getAuthnContextClassRef).collect(Collectors.toList());
                
                return acrs;
            }
        }
        
        return null;
	}

	protected void doExecute(ProfileRequestContext profileRequestContext, AuthenticationContext authenticationContext) {
		authenticationContext.getActiveResults().clear();
		LOG.info("{} Removed all active resultsto force authentication", getLogPrefix());

	}

}
