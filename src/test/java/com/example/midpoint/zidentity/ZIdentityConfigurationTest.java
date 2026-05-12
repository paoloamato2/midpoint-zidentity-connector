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

import org.identityconnectors.common.security.GuardedString;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link ZIdentityConfiguration}.
 */
class ZIdentityConfigurationTest {

    private ZIdentityConfiguration config;

    @BeforeEach
    void setUp() {
        config = new ZIdentityConfiguration();
        config.setTenant("acme");
        config.setClientId("client-id");
        config.setClientSecret(new GuardedString("secret".toCharArray()));
    }

    // ------------------------------------------------------------------
    // validate()
    // ------------------------------------------------------------------

    @Test
    @DisplayName("validate() passes when all required fields are set")
    void validate_allFieldsSet_noException() {
        assertDoesNotThrow(() -> config.validate());
    }

    @Test
    @DisplayName("validate() throws when tenant is null")
    void validate_tenantNull_throws() {
        config.setTenant(null);
        assertThrows(IllegalArgumentException.class, () -> config.validate());
    }

    @Test
    @DisplayName("validate() throws when tenant is blank")
    void validate_tenantBlank_throws() {
        config.setTenant("   ");
        assertThrows(IllegalArgumentException.class, () -> config.validate());
    }

    @Test
    @DisplayName("validate() throws when clientId is null")
    void validate_clientIdNull_throws() {
        config.setClientId(null);
        assertThrows(IllegalArgumentException.class, () -> config.validate());
    }

    @Test
    @DisplayName("validate() throws when clientSecret is null")
    void validate_clientSecretNull_throws() {
        config.setClientSecret(null);
        assertThrows(IllegalArgumentException.class, () -> config.validate());
    }

    @Test
    @DisplayName("validate() throws when pageSize is 0")
    void validate_pageSizeZero_throws() {
        config.setPageSize(0);
        assertThrows(IllegalArgumentException.class, () -> config.validate());
    }

    @Test
    @DisplayName("validate() throws when pageSize exceeds 1000")
    void validate_pageSizeOver1000_throws() {
        config.setPageSize(1001);
        assertThrows(IllegalArgumentException.class, () -> config.validate());
    }

    @Test
    @DisplayName("validate() passes when pageSize is exactly 1000")
    void validate_pageSizeAt1000_noException() {
        config.setPageSize(1000);
        assertDoesNotThrow(() -> config.validate());
    }

    // ------------------------------------------------------------------
    // Computed URL helpers
    // ------------------------------------------------------------------

    @Test
    @DisplayName("getTokenUrl() returns tenant-specific token endpoint")
    void getTokenUrl_returnsCorrectUrl() {
        assertEquals("https://acme.zslogin.net/oauth2/v1/token", config.getTokenUrl());
    }

    @Test
    @DisplayName("getApiBaseUrl() returns constant admin API base URL")
    void getApiBaseUrl_returnsConstant() {
        assertEquals("https://api.zsapi.net/ziam/admin/api/v1", config.getApiBaseUrl());
    }

    @Test
    @DisplayName("getTokenUrl() uses the tenant set via setTenant()")
    void getTokenUrl_reflectsTenantChange() {
        config.setTenant("bigcorp");
        assertTrue(config.getTokenUrl().startsWith("https://bigcorp.zslogin.net"));
    }

    // ------------------------------------------------------------------
    // Default values
    // ------------------------------------------------------------------

    @Test
    @DisplayName("Default sslVerify is true")
    void defaultSslVerify_isTrue() {
        ZIdentityConfiguration fresh = new ZIdentityConfiguration();
        assertTrue(fresh.isSslVerify());
    }

    @Test
    @DisplayName("Default fetchGroupMemberships is true")
    void defaultFetchGroupMemberships_isTrue() {
        ZIdentityConfiguration fresh = new ZIdentityConfiguration();
        assertTrue(fresh.isFetchGroupMemberships());
    }

    @Test
    @DisplayName("Default pageSize is 200")
    void defaultPageSize_is200() {
        ZIdentityConfiguration fresh = new ZIdentityConfiguration();
        assertEquals(200, fresh.getPageSize());
    }
}
