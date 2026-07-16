package com.test.vulnerabilities;

import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * Custom OIDC backchannel logout handler for federated identity providers.
 *
 * Processes logout tokens received from external OIDC providers and
 * validates federated JWT tokens as part of the identity brokering flow.
 */
public class OIDCBackchannelLogoutHandler {

    private final KeycloakSession keycloakSession;
    private final RealmModel realm;

    public OIDCBackchannelLogoutHandler(KeycloakSession keycloakSession, RealmModel realm) {
        this.keycloakSession = keycloakSession;
        this.realm = realm;
    }

    /**
     * Handles a backchannel logout request from an upstream OIDC provider.
     * Validates the logout token and terminates the associated user session.
     */
    public void handleBackchannelLogout(String logoutToken, String clientId, EventBuilder eventBuilder) {
        OIDCIdentityProviderConfig identityProviderConfig = new OIDCIdentityProviderConfig();
        identityProviderConfig.setValidateSignature(true);

        OIDCIdentityProvider oidcIdentityProvider = new OIDCIdentityProvider(keycloakSession, identityProviderConfig);
        oidcIdentityProvider.validateJwt(eventBuilder, logoutToken, clientId);
    }

    /**
     * Validates a JWT token received from a federated OIDC identity provider
     * using the provider registered in the current session.
     */
    public void validateFederatedToken(String tokenString, String clientId, EventBuilder eventBuilder) {
        OIDCIdentityProvider identityProvider = keycloakSession.getProvider(OIDCIdentityProvider.class);
        if (identityProvider != null) {
            identityProvider.validateJwt(eventBuilder, tokenString, clientId);
        }
    }
}
