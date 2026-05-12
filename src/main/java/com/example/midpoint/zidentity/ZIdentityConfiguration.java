/*
 * Copyright (c) 2010-2014 Evolveum
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example.midpoint.zidentity;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.spi.AbstractConfiguration;
import org.identityconnectors.framework.spi.ConfigurationProperty;

/**
 * Configuration properties for the Zscaler ZIdentity connector.
 * Authentication uses OAuth 2.0 client_credentials grant:
 *   POST https://<tenant>.zslogin.net/oauth2/v1/token
 * All management calls target:
 *   https://api.zsapi.net/ziam/admin/api/v1
 */
public class ZIdentityConfiguration extends AbstractConfiguration {

    private static final Log LOG = Log.getLog(ZIdentityConfiguration.class);

    /** Zscaler tenant name, e.g. "acme" → https://acme.zslogin.net */
    private String tenant;

    /** OAuth2 API client ID obtained from ZIdentity admin console. */
    private String clientId;

    /** OAuth2 API client secret (confidential). */
    private GuardedString clientSecret;

    /**
     * Whether to verify the TLS certificate of the Zscaler endpoints.
     * Disable only in non-production environments.
     */
    private boolean sslVerify = true;

    /**
     * When true the connector fetches group memberships for every user during
     * executeQuery list operations (causes one extra API call per user).
     * Set to false for better performance if group memberships are managed
     * via the Group object class instead.
     */
    private boolean fetchGroupMemberships = true;

    /**
     * Page size used for paginated list calls (1–1000).
     * A larger value reduces the number of round-trips for large tenants.
     */
    private int pageSize = 200;

    // -----------------------------------------------------------------------
    // Validation
    // -----------------------------------------------------------------------

    @Override
    public void validate() {
        if (tenant == null || tenant.trim().isEmpty())
            throw new IllegalArgumentException("Tenant must not be empty");
        if (clientId == null || clientId.trim().isEmpty())
            throw new IllegalArgumentException("Client ID must not be empty");
        if (clientSecret == null)
            throw new IllegalArgumentException("Client Secret must not be null");
        if (pageSize < 1 || pageSize > 1000)
            throw new IllegalArgumentException("Page size must be between 1 and 1000");
    }

    // -----------------------------------------------------------------------
    // Computed helpers
    // -----------------------------------------------------------------------

    /** OAuth2 token endpoint for this tenant. */
    public String getTokenUrl() {
        return "https://" + tenant + ".zslogin.net/oauth2/v1/token";
    }

    /** ZIdentity Admin API base URL (constant for all tenants). */
    public String getApiBaseUrl() {
        return "https://api.zsapi.net/ziam/admin/api/v1";
    }

    // -----------------------------------------------------------------------
    // Properties
    // -----------------------------------------------------------------------

    public String getTenant() {
        return tenant;
    }

    @ConfigurationProperty(
            displayMessageKey = "zidentity.config.tenant.display",
            helpMessageKey    = "zidentity.config.tenant.help",
            required          = true)
    public void setTenant(String tenant) {
        this.tenant = tenant;
    }

    public String getClientId() {
        return clientId;
    }

    @ConfigurationProperty(
            displayMessageKey = "zidentity.config.clientId.display",
            helpMessageKey    = "zidentity.config.clientId.help",
            required          = true)
    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public GuardedString getClientSecret() {
        return clientSecret;
    }

    @ConfigurationProperty(
            displayMessageKey = "zidentity.config.clientSecret.display",
            helpMessageKey    = "zidentity.config.clientSecret.help",
            confidential      = true,
            required          = true)
    public void setClientSecret(GuardedString clientSecret) {
        this.clientSecret = clientSecret;
    }

    public boolean isSslVerify() {
        return sslVerify;
    }

    @ConfigurationProperty(
            displayMessageKey = "zidentity.config.sslVerify.display",
            helpMessageKey    = "zidentity.config.sslVerify.help")
    public void setSslVerify(boolean sslVerify) {
        this.sslVerify = sslVerify;
    }

    public boolean isFetchGroupMemberships() {
        return fetchGroupMemberships;
    }

    @ConfigurationProperty(
            displayMessageKey = "zidentity.config.fetchGroupMemberships.display",
            helpMessageKey    = "zidentity.config.fetchGroupMemberships.help")
    public void setFetchGroupMemberships(boolean fetchGroupMemberships) {
        this.fetchGroupMemberships = fetchGroupMemberships;
    }

    public int getPageSize() {
        return pageSize;
    }

    @ConfigurationProperty(
            displayMessageKey = "zidentity.config.pageSize.display",
            helpMessageKey    = "zidentity.config.pageSize.help")
    public void setPageSize(int pageSize) {
        this.pageSize = pageSize;
    }
}
