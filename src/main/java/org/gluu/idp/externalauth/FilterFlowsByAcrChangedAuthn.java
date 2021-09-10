package org.gluu.idp.externalauth;

import java.util.Iterator;
import java.util.Map;

import org.gluu.util.StringHelper;
import org.opensaml.profile.context.ProfileRequestContext;
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

		Object requestedAcrObject = authenticationContext.getAuthenticationStateMap().get(ShibOxAuthAuthServlet.OXAUTH_ACR_USED);
		String requestedAcr = requestedAcrObject instanceof String ? (String) requestedAcrObject : null;

		LOG.trace("{} Used ACR: {}, requested ACR: {}", getLogPrefix(), usedAcr, requestedAcr);

		if (StringHelper.equals(usedAcr, requestedAcr)) {
			LOG.debug("{} Used and requested ACR is the same: {}, nothing to do", getLogPrefix(), usedAcr);
			return false;
		}

		LOG.debug("{} Force to create new AuthZ request with new ACR: {}, nothing to do", getLogPrefix(), requestedAcr);
		return true;
	}

	protected void doExecute(ProfileRequestContext profileRequestContext, AuthenticationContext authenticationContext) {
		Map potentialFlows = authenticationContext.getPotentialFlows();

		if (potentialFlows.size() == 0) {
			LOG.info("{} No potential authentication flows remain after filtering", getLogPrefix());
		} else {
			LOG.debug("{} Potential authentication flows left after filtering: {}", getLogPrefix(), potentialFlows);
		}
	}

}
