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
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link ZIdentityConnector} — focuses on schema definition
 * and lifecycle operations that do not require a live API.
 */
class ZIdentityConnectorSchemaTest {

    private ZIdentityConnector connector;

    @BeforeEach
    void setUp() {
        // Build a minimal valid configuration without actually connecting
        ZIdentityConfiguration config = new ZIdentityConfiguration();
        config.setTenant("acme");
        config.setClientId("test-client");
        config.setClientSecret(new GuardedString("test-secret".toCharArray()));

        connector = new ZIdentityConnector();
        // We cannot call init() without a reachable endpoint, so we test
        // schema() independently via a fresh, manually wired connector.
        // schema() relies only on static definitions — no HTTP calls.
    }

    // ------------------------------------------------------------------
    // schema() — static introspection, no HTTP required
    // ------------------------------------------------------------------

    @Test
    @DisplayName("schema() defines __ACCOUNT__ object class")
    void schema_definesAccountClass() {
        Schema schema = buildSchema();
        assertNotNull(schema.findObjectClassInfo(ObjectClass.ACCOUNT_NAME),
                "__ACCOUNT__ object class must be present in schema");
    }

    @Test
    @DisplayName("schema() defines Group object class")
    void schema_definesGroupClass() {
        Schema schema = buildSchema();
        assertNotNull(schema.findObjectClassInfo(ZIdentityConnector.GROUP_CLASS),
                "Group object class must be present in schema");
    }

    @Test
    @DisplayName("__ACCOUNT__ has __ENABLE__ operational attribute")
    void schema_accountHasEnableAttribute() {
        Schema schema = buildSchema();
        var accountInfo = schema.findObjectClassInfo(ObjectClass.ACCOUNT_NAME);
        Optional<AttributeInfo> enableAttr = accountInfo.getAttributeInfo().stream()
                .filter(a -> OperationalAttributes.ENABLE_NAME.equals(a.getName()))
                .findFirst();
        assertTrue(enableAttr.isPresent(), "__ENABLE__ must be in __ACCOUNT__ schema");
    }

    @Test
    @DisplayName("__ACCOUNT__ has __PASSWORD__ operational attribute")
    void schema_accountHasPasswordAttribute() {
        Schema schema = buildSchema();
        var accountInfo = schema.findObjectClassInfo(ObjectClass.ACCOUNT_NAME);
        Optional<AttributeInfo> pwdAttr = accountInfo.getAttributeInfo().stream()
                .filter(a -> OperationalAttributes.PASSWORD_NAME.equals(a.getName()))
                .findFirst();
        assertTrue(pwdAttr.isPresent(), "__PASSWORD__ must be in __ACCOUNT__ schema");
    }

    @Test
    @DisplayName("__ACCOUNT__ has 'groups' multi-valued attribute")
    void schema_accountHasGroupsAttribute() {
        Schema schema = buildSchema();
        var accountInfo = schema.findObjectClassInfo(ObjectClass.ACCOUNT_NAME);
        Optional<AttributeInfo> groupsAttr = accountInfo.getAttributeInfo().stream()
                .filter(a -> "groups".equals(a.getName()))
                .findFirst();
        assertTrue(groupsAttr.isPresent(), "groups attribute must be in __ACCOUNT__ schema");
        assertTrue(groupsAttr.get().isMultiValued(), "groups must be multi-valued");
    }

    @Test
    @DisplayName("Group has 'description' attribute")
    void schema_groupHasDescriptionAttribute() {
        Schema schema = buildSchema();
        var groupInfo = schema.findObjectClassInfo(ZIdentityConnector.GROUP_CLASS);
        Optional<AttributeInfo> descAttr = groupInfo.getAttributeInfo().stream()
                .filter(a -> "description".equals(a.getName()))
                .findFirst();
        assertTrue(descAttr.isPresent(), "description must be in Group schema");
    }

    @Test
    @DisplayName("__UID__ is read-only and not creatable in __ACCOUNT__")
    void schema_accountUidIsReadOnly() {
        Schema schema = buildSchema();
        var accountInfo = schema.findObjectClassInfo(ObjectClass.ACCOUNT_NAME);
        Optional<AttributeInfo> uidAttr = accountInfo.getAttributeInfo().stream()
                .filter(a -> org.identityconnectors.framework.common.objects.Uid.NAME.equals(a.getName()))
                .findFirst();
        assertTrue(uidAttr.isPresent());
        assertFalse(uidAttr.get().isCreateable(), "__UID__ must not be createable");
        assertFalse(uidAttr.get().isUpdateable(), "__UID__ must not be updateable");
        assertTrue(uidAttr.get().isReadable(),    "__UID__ must be readable");
    }

    // ------------------------------------------------------------------
    // dispose() — no-op safety check
    // ------------------------------------------------------------------

    @Test
    @DisplayName("dispose() can be called without throwing")
    void dispose_doesNotThrow() {
        // connector was never init()-ed; dispose should still be safe
        assertDoesNotThrow(() -> connector.dispose());
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    /**
     * Calls schema() on a freshly constructed (not init()-ed) connector.
     * schema() has no external dependencies so this is safe.
     */
    private Schema buildSchema() {
        return connector.schema();
    }
}
