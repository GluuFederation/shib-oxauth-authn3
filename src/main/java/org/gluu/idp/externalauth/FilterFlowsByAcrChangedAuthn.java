package org.gluu.idp.externalauth;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.gluu.util.StringHelper;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.AuthenticationResult;
import net.shibboleth.idp.authn.context.AuthenticationContext;

/**
 * @author Yuriy Movchan on 09/13/2021
 */
public class FilterFlowsByAcrChangedAuthn extends AbstractAuthenticationAction {

	private static final String OX_AUTH_FLOW_ID = "authn/oxAuth";
	private final Logger LOG = LoggerFactory.getLogger(FilterFlowsByAcrChangedAuthn.class);
	
	private boolean disabled = false;

	public FilterFlowsByAcrChangedAuthn() {
	}

	protected boolean doPreExecute(ProfileRequestContext profileRequestContext,
			AuthenticationContext authenticationContext) {
		if (!super.doPreExecute(profileRequestContext, authenticationContext)) {
			return false;
		}
		
		if (disabled) {
			return false;
		}
		
		Map<String, AuthenticationResult> activeResultsMap = authenticationContext.getActiveResults();
		if (!activeResultsMap.containsKey(OX_AUTH_FLOW_ID)) {
			LOG.debug("{} Session does not have authn/oxAuth results, nothing to do", getLogPrefix());
			return false;
		}

		AuthenticationResult authenticationResult = authenticationContext.getActiveResults().get(OX_AUTH_FLOW_ID);
		String usedAcr = authenticationResult.getAdditionalData().get(ShibOxAuthAuthServlet.OXAUTH_ACR_USED);
		String previousRequestedAcr = authenticationResult.getAdditionalData().get(ShibOxAuthAuthServlet.OXAUTH_ACR_REQUESTED);

		List<String> requestedAcrs = determineAcrs(profileRequestContext);
		LOG.debug("{} Used ACR: {}:{}, requested ACRs: {}", getLogPrefix(), usedAcr, previousRequestedAcr, requestedAcrs);
		
		if ((requestedAcrs == null) || (requestedAcrs.size() == 0)) {
			LOG.debug("{} There is no requested ACRs , nothing to do", getLogPrefix());
			return false;
		}
		
		for (String requestedAcr : requestedAcrs) {
			if (StringHelper.equals(usedAcr, requestedAcr) || StringHelper.equals(previousRequestedAcr, requestedAcr)) {
				LOG.debug("{} Used and requested ACR are the same: {}, nothing to do", getLogPrefix(), usedAcr);
				return false;
			}
		}

		LOG.debug("{} Force to create new AuthZ request with new ACRs: {}, nothing to do", getLogPrefix(), requestedAcrs);
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
		if (!disabled) {
			authenticationContext.getActiveResults().clear();
			LOG.info("{} Removed all active results to force authentication", getLogPrefix());
		}
	}

	public boolean isDisabled() {
		return disabled;
	}

	public void setDisabled(boolean disabled) {
		this.disabled = disabled;
	}

}
