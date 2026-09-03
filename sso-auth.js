/**
 * KeePass Web Team Edition - Single Sign-On (SSO) Integration Engine
 * Supports OpenID Connect (OIDC), OAuth2, and simulated enterprise IDP
 */

const crypto = require('crypto');

// SSO Identity Provider Configurations
const SSO_PROVIDERS = {
    google: {
        name: 'Google Workspace',
        icon: '🌐',
        authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
        tokenUrl: 'https://oauth2.googleapis.com/token',
        userInfoUrl: 'https://openidconnect.googleapis.com/v1/userinfo',
        scopes: ['openid', 'profile', 'email']
    },
    microsoft: {
        name: 'Microsoft 365 / Entra ID',
        icon: '🏢',
        authUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
        tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
        userInfoUrl: 'https://graph.microsoft.com/oidc/userinfo',
        scopes: ['openid', 'profile', 'email']
    },
    okta: {
        name: 'Okta Enterprise SSO',
        icon: '🛡️',
        authUrl: process.env.OKTA_AUTH_URL || 'https://company.okta.com/oauth2/v1/authorize',
        tokenUrl: process.env.OKTA_TOKEN_URL || 'https://company.okta.com/oauth2/v1/token',
        userInfoUrl: process.env.OKTA_USERINFO_URL || 'https://company.okta.com/oauth2/v1/userinfo',
        scopes: ['openid', 'profile', 'email', 'groups']
    },
    generic_oidc: {
        name: 'Enterprise OIDC / Keycloak',
        icon: '🔑',
        authUrl: process.env.OIDC_AUTH_URL || 'https://sso.company.internal/auth/realms/master/protocol/openid-connect/auth',
        tokenUrl: process.env.OIDC_TOKEN_URL || 'https://sso.company.internal/auth/realms/master/protocol/openid-connect/token',
        userInfoUrl: process.env.OIDC_USERINFO_URL || 'https://sso.company.internal/auth/realms/master/protocol/openid-connect/userinfo',
        scopes: ['openid', 'profile', 'email', 'groups']
    }
};

// In-flight OAuth states for CSRF protection
const activeStates = new Map();

/**
 * Generate OAuth authorization URL
 */
function getAuthorizationUrl(providerKey, redirectUri) {
    const provider = SSO_PROVIDERS[providerKey] || SSO_PROVIDERS.google;
    const state = crypto.randomBytes(16).toString('hex');
    const nonce = crypto.randomBytes(16).toString('hex');

    activeStates.set(state, {
        providerKey,
        nonce,
        createdAt: Date.now()
    });

    // Cleanup expired states (>10 minutes)
    for (const [s, data] of activeStates.entries()) {
        if (Date.now() - data.createdAt > 600000) {
            activeStates.delete(s);
        }
    }

    const clientId = process.env[`SSO_${providerKey.toUpperCase()}_CLIENT_ID`] || `client_keepass_${providerKey}_demo`;
    const params = new URLSearchParams({
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope: provider.scopes.join(' '),
        state: state,
        nonce: nonce
    });

    return `${provider.authUrl}?${params.toString()}`;
}

/**
 * Handle SSO callback and map claims to local user role
 */
function mapSSOProfileToUser(ssoProfile) {
    const email = ssoProfile.email || `${ssoProfile.sub || 'user'}@sso.local`;
    const username = ssoProfile.preferred_username || email.split('@')[0].toLowerCase().replace(/[^a-z0-9_]/g, '_');
    const displayName = ssoProfile.name || ssoProfile.displayName || username;

    // Role mapping based on group claims or email domain
    let role = 'member';
    const groups = ssoProfile.groups || [];
    if (groups.includes('VaultAdmins') || groups.includes('Domain Admins') || email.startsWith('admin@')) {
        role = 'admin';
    } else if (groups.includes('DevOps') || groups.includes('VaultManagers') || email.startsWith('lead@')) {
        role = 'manager';
    }

    return {
        ssoProvider: ssoProfile.provider || 'sso',
        ssoSub: ssoProfile.sub || ssoProfile.id || username,
        username,
        displayName,
        email,
        role,
        avatar: '🏢'
    };
}

/**
 * Mock SSO verification for instant local team demonstration
 */
function handleMockSSOLogin(providerKey, roleOverride = 'member') {
    const mockProfiles = {
        admin_sso: {
            sub: 'sso_admin_001',
            name: 'DevOps Administrator (SSO)',
            email: 'admin.sso@company.com',
            groups: ['VaultAdmins', 'DevOps'],
            provider: providerKey
        },
        engineer_sso: {
            sub: 'sso_eng_002',
            name: 'Cloud Engineer (SSO)',
            email: 'engineer.sso@company.com',
            groups: ['DevOps'],
            provider: providerKey
        },
        guest_sso: {
            sub: 'sso_member_003',
            name: 'Team Member (SSO)',
            email: 'member.sso@company.com',
            groups: ['TeamMembers'],
            provider: providerKey
        }
    };

    const profile = mockProfiles[roleOverride] || mockProfiles.engineer_sso;
    return mapSSOProfileToUser(profile);
}

module.exports = {
    SSO_PROVIDERS,
    getAuthorizationUrl,
    mapSSOProfileToUser,
    handleMockSSOLogin
};
