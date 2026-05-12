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

import com.google.gson.JsonObject;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.FrameworkUtil;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeDelta;
import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.AttributeInfoBuilder;
import org.identityconnectors.framework.common.objects.AttributesAccessor;
import org.identityconnectors.framework.common.objects.BaseConnectorObject;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.identityconnectors.framework.common.objects.ConnectorObjectReference;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfoBuilder;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.OperationalAttributeInfos;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.SchemaBuilder;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.AttributeFilter;
import org.identityconnectors.framework.common.objects.filter.Filter;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.Connector;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.operations.CreateOp;
import org.identityconnectors.framework.spi.operations.DeleteOp;
import org.identityconnectors.framework.spi.operations.SchemaOp;
import org.identityconnectors.framework.spi.operations.SearchOp;
import org.identityconnectors.framework.spi.operations.TestOp;
import org.identityconnectors.framework.spi.operations.UpdateDeltaOp;
import org.identityconnectors.framework.spi.operations.UpdateOp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Zscaler ZIdentity connector for MidPoint / ConnId.
 *
 * <h2>Supported object classes</h2>
 * <ul>
 *   <li>{@code __ACCOUNT__} - ZIdentity Users</li>
 *   <li>{@code Group}       - ZIdentity Groups</li>
 * </ul>
 *
 * <h2>Supported operations</h2>
 * TestOp, SchemaOp, CreateOp, DeleteOp,
 * SearchOp, UpdateOp, UpdateDeltaOp
 *
 * <h2>Authentication</h2>
 * OAuth 2.0 {@code client_credentials} grant via the tenant-specific
 * token endpoint. The access token is cached and refreshed automatically.
 *
 * <h2>Group membership</h2>
 * The {@code groups} attribute on {@code __ACCOUNT__} is a multi-valued
 * {@link ConnectorObjectReference} with {@code SUBJECT} role.  Changes to this
 * attribute (add / remove / replace) are translated to the appropriate
 * {@code POST /groups/{id}/users/{userId}} or
 * {@code DELETE /groups/{id}/users/{userId}} API calls.
 */
@ConnectorClass(displayNameKey = "zidentity.connector.display",
                configurationClass = ZIdentityConfiguration.class)
public class ZIdentityConnector
        implements Connector, TestOp, SchemaOp, CreateOp, DeleteOp,
                   SearchOp<Filter>, UpdateOp, UpdateDeltaOp {

    private static final Log LOG = Log.getLog(ZIdentityConnector.class);

    /** ConnId object class name for ZIdentity Groups. */
    static final String GROUP_CLASS = "Group";

    private ZIdentityConfiguration configuration;
    private ZIdentityClient client;

    // -----------------------------------------------------------------------
    // Connector lifecycle
    // -----------------------------------------------------------------------

    @Override
    public Configuration getConfiguration() {
        return configuration;
    }

    @Override
    public void init(Configuration configuration) {
        LOG.ok("Initialising ZIdentity connector");
        this.configuration = (ZIdentityConfiguration) configuration;
        this.client = new ZIdentityClient(this.configuration);
        LOG.ok("ZIdentity connector initialised");
    }

    @Override
    public void dispose() {
        configuration = null;
        client = null;
    }

    // -----------------------------------------------------------------------
    // TestOp
    // -----------------------------------------------------------------------

    @Override
    public void test() {
        LOG.ok("START test");
        try {
            client.testConnection();
        } catch (Exception e) {
            LOG.error("Connection test failed: {0}", e.getMessage());
            throw new ConnectorException("Connection test failed", e);
        }
        LOG.ok("END test - OK");
    }

    // -----------------------------------------------------------------------
    // SchemaOp
    // -----------------------------------------------------------------------

    @Override
    public Schema schema() {
        LOG.ok("START schema");
        SchemaBuilder schemaBuilder = new SchemaBuilder(ZIdentityConnector.class);

        // ── User (__ACCOUNT__) ─────────────────────────────────────────────
        ObjectClassInfoBuilder userBuilder = new ObjectClassInfoBuilder();
        // Default type = __ACCOUNT__

        // __UID__ maps to the system-assigned id field (read-only)
        AttributeInfoBuilder uidAib = new AttributeInfoBuilder(Uid.NAME);
        uidAib.setNativeName("id");
        uidAib.setType(String.class);
        uidAib.setRequired(false);   // absent on create
        uidAib.setCreateable(false);
        uidAib.setUpdateable(false);
        uidAib.setReadable(true);
        userBuilder.addAttributeInfo(uidAib.build());

        // __NAME__ maps to loginName (unique, human-readable identifier)
        AttributeInfoBuilder nameAib = new AttributeInfoBuilder(Name.NAME);
        nameAib.setNativeName("loginName");
        nameAib.setType(String.class);
        nameAib.setRequired(true);
        userBuilder.addAttributeInfo(nameAib.build());

        // __ENABLE__ maps to status (true = active)
        userBuilder.addAttributeInfo(OperationalAttributeInfos.ENABLE);

        // __PASSWORD__ write-only
        userBuilder.addAttributeInfo(OperationalAttributeInfos.PASSWORD);

        // Writable user attributes
        userBuilder.addAttributeInfo(AttributeInfoBuilder.build("displayName",     String.class));
        userBuilder.addAttributeInfo(AttributeInfoBuilder.build("firstName",       String.class));
        userBuilder.addAttributeInfo(AttributeInfoBuilder.build("lastName",        String.class));
        userBuilder.addAttributeInfo(AttributeInfoBuilder.build("primaryEmail",    String.class));
        userBuilder.addAttributeInfo(AttributeInfoBuilder.build("secondaryEmail",  String.class));
        userBuilder.addAttributeInfo(AttributeInfoBuilder.build("departmentId",    String.class));

        // Read-only metadata
        AttributeInfoBuilder sourceAib = new AttributeInfoBuilder("source");
        sourceAib.setType(String.class);
        sourceAib.setCreateable(false);
        sourceAib.setUpdateable(false);
        sourceAib.setReadable(true);
        userBuilder.addAttributeInfo(sourceAib.build());

        // groups - multi-valued ConnectorObjectReference (SUBJECT side)
        AttributeInfoBuilder groupsAib = new AttributeInfoBuilder("groups");
        groupsAib.setType(ConnectorObjectReference.class);
        groupsAib.setMultiValued(true);
        groupsAib.setReferencedObjectClassName(GROUP_CLASS);
        groupsAib.setRoleInReference(String.valueOf(AttributeInfo.RoleInReference.SUBJECT));
        FrameworkUtil.checkAttributeType(ConnectorObjectReference.class);
        userBuilder.addAttributeInfo(groupsAib.build());

        schemaBuilder.defineObjectClass(userBuilder.build());

        // ── Group ──────────────────────────────────────────────────────────
        ObjectClassInfoBuilder groupBuilder = new ObjectClassInfoBuilder();
        groupBuilder.setType(GROUP_CLASS);

        // __UID__ maps to id (read-only)
        AttributeInfoBuilder gUidAib = new AttributeInfoBuilder(Uid.NAME);
        gUidAib.setNativeName("id");
        gUidAib.setType(String.class);
        gUidAib.setRequired(false);
        gUidAib.setCreateable(false);
        gUidAib.setUpdateable(false);
        gUidAib.setReadable(true);
        groupBuilder.addAttributeInfo(gUidAib.build());

        // __NAME__ maps to name
        AttributeInfoBuilder gNameAib = new AttributeInfoBuilder(Name.NAME);
        gNameAib.setNativeName("name");
        gNameAib.setType(String.class);
        gNameAib.setRequired(true);
        groupBuilder.addAttributeInfo(gNameAib.build());

        groupBuilder.addAttributeInfo(AttributeInfoBuilder.build("description", String.class));

        // Read-only group metadata
        AttributeInfoBuilder isDynamicAib = new AttributeInfoBuilder("isDynamicGroup");
        isDynamicAib.setType(Boolean.class);
        isDynamicAib.setCreateable(false);
        isDynamicAib.setUpdateable(false);
        isDynamicAib.setReadable(true);
        groupBuilder.addAttributeInfo(isDynamicAib.build());

        AttributeInfoBuilder gSourceAib = new AttributeInfoBuilder("source");
        gSourceAib.setType(String.class);
        gSourceAib.setCreateable(false);
        gSourceAib.setUpdateable(false);
        gSourceAib.setReadable(true);
        groupBuilder.addAttributeInfo(gSourceAib.build());

        // members - read-only, populated only for single-group reads
        AttributeInfoBuilder membersAib = new AttributeInfoBuilder("members");
        membersAib.setType(String.class);
        membersAib.setMultiValued(true);
        membersAib.setCreateable(false);
        membersAib.setUpdateable(false);
        membersAib.setReadable(true);
        groupBuilder.addAttributeInfo(membersAib.build());

        schemaBuilder.defineObjectClass(groupBuilder.build());

        LOG.ok("END schema");
        return schemaBuilder.build();
    }

    // -----------------------------------------------------------------------
    // CreateOp
    // -----------------------------------------------------------------------

    @Override
    public Uid create(ObjectClass objectClass, Set<Attribute> attributes, OperationOptions options) {
        LOG.ok("START create objectClass={0}", objectClass.getObjectClassValue());
        AttributesAccessor accessor = new AttributesAccessor(attributes);
        try {
            if (ObjectClass.ACCOUNT.equals(objectClass)) {
                return createUser(accessor);
            }
            if (new ObjectClass(GROUP_CLASS).equals(objectClass)) {
                return createGroup(accessor);
            }
            throw new ConnectorException("Unknown object class: " + objectClass.getObjectClassValue());
        } catch (ConnectorException e) {
            throw e;
        } catch (Exception e) {
            LOG.error("create ERROR: {0}\n{1}", e, Arrays.toString(e.getStackTrace()));
            throw new ConnectorException(e);
        }
    }

    private Uid createUser(AttributesAccessor accessor) {
        Map<String, Object> payload = buildUserPayload(accessor, null);

        LOG.ok("Creating user loginName={0}", payload.get("loginName"));
        String userId = client.createUser(payload);
        LOG.ok("User created id={0}", userId);

        // Set password if provided
        GuardedString gs = accessor.getPassword();
        if (gs != null) {
            final StringBuilder clear = new StringBuilder();
            gs.access(chars -> clear.append(chars));
            try {
                client.updateUserPassword(userId, clear.toString(), false);
            } finally {
                for (int i = 0; i < clear.length(); i++) clear.setCharAt(i, '\0');
            }
        }

        // Add group memberships
        Attribute groupsAttr = accessor.find("groups");
        if (groupsAttr != null && groupsAttr.getValue() != null) {
            for (Object v : groupsAttr.getValue()) {
                String groupId = extractGroupId(v);
                client.addUserToGroup(groupId, userId);
                LOG.ok("User {0} added to group {1}", userId, groupId);
            }
        }

        LOG.ok("END createUser uid={0}", userId);
        return new Uid(userId);
    }

    private Uid createGroup(AttributesAccessor accessor) {
        String name = accessor.findString(Name.NAME);
        if (name == null || name.trim().isEmpty())
            throw new ConnectorException("Group name (__NAME__) is required");

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("name", name);
        String description = accessor.findString("description");
        if (description != null) payload.put("description", description);

        LOG.ok("Creating group name={0}", name);
        String groupId = client.createGroup(payload);
        LOG.ok("Group created id={0}", groupId);
        return new Uid(groupId);
    }

    // -----------------------------------------------------------------------
    // DeleteOp
    // -----------------------------------------------------------------------

    @Override
    public void delete(ObjectClass objectClass, Uid uid, OperationOptions options) {
        LOG.ok("START delete objectClass={0} uid={1}", objectClass.getObjectClassValue(), uid.getUidValue());
        try {
            if (ObjectClass.ACCOUNT.equals(objectClass)) {
                client.deleteUser(uid.getUidValue());
                LOG.ok("User {0} deleted", uid.getUidValue());
                return;
            }
            if (new ObjectClass(GROUP_CLASS).equals(objectClass)) {
                client.deleteGroup(uid.getUidValue());
                LOG.ok("Group {0} deleted", uid.getUidValue());
                return;
            }
            throw new ConnectorException("Unknown object class: " + objectClass.getObjectClassValue());
        } catch (UnknownUidException e) {
            throw e;
        } catch (ConnectorException e) {
            throw e;
        } catch (Exception e) {
            LOG.error("delete ERROR: {0}\n{1}", e, Arrays.toString(e.getStackTrace()));
            throw new ConnectorException(e);
        }
    }

    // -----------------------------------------------------------------------
    // SearchOp
    // -----------------------------------------------------------------------

    @Override
    public FilterTranslator<Filter> createFilterTranslator(ObjectClass objectClass, OperationOptions options) {
        return filter -> {
            List<Filter> list = new ArrayList<>(1);
            if (filter instanceof AttributeFilter) {
                list.add(filter);
            }
            return list;
        };
    }

    @Override
    public void executeQuery(ObjectClass objectClass, Filter query, ResultsHandler handler, OperationOptions options) {
        LOG.ok("START executeQuery objectClass={0} query={1}", objectClass.getObjectClassValue(), query);

        // Parse filter into UID / NAME lookup keys
        Map<String, String> filterKeys = new HashMap<>();
        if (query != null) {
            List<Filter> filters = createFilterTranslator(objectClass, options).translate(query);
            for (Filter f : filters) {
                if (f instanceof AttributeFilter) {
                    AttributeFilter af = (AttributeFilter) f;
                    String attrName = af.getAttribute().getName();
                    String attrVal  = af.getAttribute().getValue().get(0).toString();
                    if (Uid.NAME.equalsIgnoreCase(attrName)) {
                        filterKeys.put("uid", attrVal);
                    } else if (Name.NAME.equalsIgnoreCase(attrName)) {
                        filterKeys.put("name", attrVal);
                    } else {
                        filterKeys.put(attrName, attrVal);
                    }
                }
            }
        }

        try {
            if (ObjectClass.ACCOUNT.equals(objectClass)) {
                executeQueryUsers(filterKeys, handler, options);
            } else if (new ObjectClass(GROUP_CLASS).equals(objectClass)) {
                executeQueryGroups(filterKeys, handler, options);
            } else {
                throw new ConnectorException("Unknown object class: " + objectClass.getObjectClassValue());
            }
        } catch (ConnectorException e) {
            throw e;
        } catch (Exception e) {
            LOG.error("executeQuery ERROR: {0}\n{1}", e, Arrays.toString(e.getStackTrace()));
            throw new ConnectorException(e);
        }
        LOG.ok("END executeQuery");
    }

    private void executeQueryUsers(Map<String, String> filterKeys, ResultsHandler handler, OperationOptions options) {
        if (filterKeys.containsKey("uid")) {
            // Single user get by system ID
            String uid = filterKeys.get("uid");
            LOG.ok("Fetching user by UID {0}", uid);
            JsonObject userJson = client.getUser(uid);
            handler.handle(buildUserConnectorObject(userJson, true));
            return;
        }

        if (filterKeys.containsKey("name")) {
            // Single user get by loginName
            String loginName = filterKeys.get("name");
            LOG.ok("Fetching user by loginName {0}", loginName);
            Map<String, String> params = new HashMap<>();
            params.put("loginname", loginName);
            List<JsonObject> page = client.listUsersPage(0, configuration.getPageSize(), params);
            for (JsonObject u : page) {
                // Verify exact match since the API does exact-match on loginname
                String foundLogin = safeGetString(u, "loginName");
                if (loginName.equalsIgnoreCase(foundLogin)) {
                    handler.handle(buildUserConnectorObject(u, true));
                }
            }
            return;
        }

        // Full list - stream page by page
        boolean fetchGroups = configuration.isFetchGroupMemberships();
        int offset    = 0;
        int pageSize  = configuration.getPageSize();
        while (true) {
            List<JsonObject> page = client.listUsersPage(offset, pageSize, null);
            LOG.ok("Fetched users page offset={0} count={1}", offset, page.size());
            for (JsonObject u : page) {
                ConnectorObject obj = buildUserConnectorObject(u, fetchGroups);
                if (!handler.handle(obj)) {
                    LOG.ok("ResultsHandler requested stop");
                    return;
                }
            }
            if (page.size() < pageSize) break;
            offset += pageSize;
        }
    }

    private void executeQueryGroups(Map<String, String> filterKeys, ResultsHandler handler, OperationOptions options) {
        if (filterKeys.containsKey("uid")) {
            String uid = filterKeys.get("uid");
            LOG.ok("Fetching group by UID {0}", uid);
            JsonObject groupJson = client.getGroup(uid);
            handler.handle(buildGroupConnectorObject(groupJson, true));
            return;
        }

        if (filterKeys.containsKey("name")) {
            // Use name[like] and filter client-side for exact match
            String name = filterKeys.get("name");
            LOG.ok("Fetching group by name {0}", name);
            Map<String, String> params = new HashMap<>();
            params.put("name[like]", name);
            List<JsonObject> page = client.listGroupsPage(0, configuration.getPageSize(), params);
            for (JsonObject g : page) {
                if (name.equalsIgnoreCase(safeGetString(g, "name"))) {
                    handler.handle(buildGroupConnectorObject(g, true));
                }
            }
            return;
        }

        // Full list - stream page by page (no member fetch for performance)
        int offset   = 0;
        int pageSize = configuration.getPageSize();
        while (true) {
            List<JsonObject> page = client.listGroupsPage(offset, pageSize, null);
            LOG.ok("Fetched groups page offset={0} count={1}", offset, page.size());
            for (JsonObject g : page) {
                if (!handler.handle(buildGroupConnectorObject(g, false))) {
                    LOG.ok("ResultsHandler requested stop");
                    return;
                }
            }
            if (page.size() < pageSize) break;
            offset += pageSize;
        }
    }

    // -----------------------------------------------------------------------
    // UpdateOp  (full replace)
    // -----------------------------------------------------------------------

    @Override
    public Uid update(ObjectClass objectClass, Uid uid, Set<Attribute> attributes, OperationOptions options) {
        LOG.ok("START update objectClass={0} uid={1}", objectClass.getObjectClassValue(), uid.getUidValue());
        AttributesAccessor accessor = new AttributesAccessor(attributes);
        try {
            if (ObjectClass.ACCOUNT.equals(objectClass)) {
                return updateUser(uid.getUidValue(), accessor);
            }
            if (new ObjectClass(GROUP_CLASS).equals(objectClass)) {
                return updateGroup(uid.getUidValue(), accessor);
            }
            throw new ConnectorException("Unknown object class: " + objectClass.getObjectClassValue());
        } catch (ConnectorException e) {
            throw e;
        } catch (Exception e) {
            LOG.error("update ERROR: {0}\n{1}", e, Arrays.toString(e.getStackTrace()));
            throw new ConnectorException(e);
        }
    }

    private Uid updateUser(String userId, AttributesAccessor accessor) {
        // Fetch current state to fill required fields that may not be supplied
        JsonObject current = client.getUser(userId);

        Map<String, Object> payload = buildUserPayload(accessor, current);
        client.updateUser(userId, payload);
        LOG.ok("User {0} updated", userId);

        // Handle password change
        GuardedString gs = accessor.getPassword();
        if (gs != null) {
            final StringBuilder clear = new StringBuilder();
            gs.access(chars -> clear.append(chars));
            try {
                client.updateUserPassword(userId, clear.toString(), false);
            } finally {
                for (int i = 0; i < clear.length(); i++) clear.setCharAt(i, '\0');
            }
        }

        // Reconcile group memberships (full replace semantics)
        Attribute groupsAttr = accessor.find("groups");
        if (groupsAttr != null) {
            Set<String> desired = extractGroupIds(
                    groupsAttr.getValue() != null ? groupsAttr.getValue() : Collections.emptyList());
            reconcileGroupMemberships(userId, desired);
        }

        return new Uid(userId);
    }

    private Uid updateGroup(String groupId, AttributesAccessor accessor) {
        JsonObject current = client.getGroup(groupId);
        Map<String, Object> payload = new LinkedHashMap<>();

        String name = accessor.findString(Name.NAME);
        payload.put("name", name != null ? name : safeGetString(current, "name"));

        String description = accessor.findString("description");
        if (description != null) {
            payload.put("description", description);
        } else if (current.has("description") && !current.get("description").isJsonNull()) {
            payload.put("description", current.get("description").getAsString());
        }

        client.updateGroup(groupId, payload);
        LOG.ok("Group {0} updated", groupId);
        return new Uid(groupId);
    }

    // -----------------------------------------------------------------------
    // UpdateDeltaOp  (incremental)
    // -----------------------------------------------------------------------

    @Override
    public Set<AttributeDelta> updateDelta(ObjectClass objectClass, Uid uid,
                                           Set<AttributeDelta> deltas, OperationOptions options) {
        LOG.ok("START updateDelta objectClass={0} uid={1}", objectClass.getObjectClassValue(), uid.getUidValue());
        try {
            if (ObjectClass.ACCOUNT.equals(objectClass)) {
                updateDeltaUser(uid.getUidValue(), deltas);
                return Collections.emptySet();
            }
            if (new ObjectClass(GROUP_CLASS).equals(objectClass)) {
                updateDeltaGroup(uid.getUidValue(), deltas);
                return Collections.emptySet();
            }
            throw new ConnectorException("Unknown object class: " + objectClass.getObjectClassValue());
        } catch (ConnectorException e) {
            throw e;
        } catch (Exception e) {
            LOG.error("updateDelta ERROR: {0}\n{1}", e, Arrays.toString(e.getStackTrace()));
            throw new ConnectorException(e);
        }
    }

    private void updateDeltaUser(String userId, Set<AttributeDelta> deltas) {
        // Separate structural deltas from groups and password deltas
        boolean hasStructuralDelta = false;
        for (AttributeDelta d : deltas) {
            String n = d.getName();
            if (!"groups".equalsIgnoreCase(n) && !OperationalAttributes.PASSWORD_NAME.equalsIgnoreCase(n)) {
                hasStructuralDelta = true;
                break;
            }
        }

        if (hasStructuralDelta) {
            // Fetch current, apply deltas, PUT
            JsonObject current = client.getUser(userId);
            Map<String, Object> payload = buildCurrentUserPayload(current);

            for (AttributeDelta delta : deltas) {
                String name = delta.getName();
                if ("groups".equalsIgnoreCase(name) || OperationalAttributes.PASSWORD_NAME.equalsIgnoreCase(name))
                    continue;

                List<Object> values = delta.getValuesToReplace() != null ? delta.getValuesToReplace()
                        : (delta.getValuesToAdd() != null ? delta.getValuesToAdd() : Collections.emptyList());
                if (values.isEmpty()) continue;

                if (Name.NAME.equalsIgnoreCase(name)) {
                    payload.put("loginName", values.get(0).toString());
                } else if ("displayName".equalsIgnoreCase(name)) {
                    payload.put("displayName", values.get(0).toString());
                } else if ("primaryEmail".equalsIgnoreCase(name)) {
                    payload.put("primaryEmail", values.get(0).toString());
                } else if (OperationalAttributes.ENABLE_NAME.equalsIgnoreCase(name)) {
                    payload.put("status", (Boolean) values.get(0));
                } else if ("firstName".equalsIgnoreCase(name)) {
                    payload.put("firstName", values.get(0).toString());
                } else if ("lastName".equalsIgnoreCase(name)) {
                    payload.put("lastName", values.get(0).toString());
                } else if ("secondaryEmail".equalsIgnoreCase(name)) {
                    payload.put("secondaryEmail", values.get(0).toString());
                } else if ("departmentId".equalsIgnoreCase(name)) {
                    Map<String, String> dept = new LinkedHashMap<>();
                    dept.put("id", values.get(0).toString());
                    payload.put("department", dept);
                } else {
                    LOG.warn("Ignoring unknown attribute delta: {0}", name);
                }
            }
            client.updateUser(userId, payload);
            LOG.ok("User {0} attributes updated via delta", userId);
        }

        // Handle password delta
        for (AttributeDelta delta : deltas) {
            if (!OperationalAttributes.PASSWORD_NAME.equalsIgnoreCase(delta.getName())) continue;
            List<Object> values = delta.getValuesToReplace();
            if (values == null || values.isEmpty()) continue;
            GuardedString gs = (GuardedString) values.get(0);
            final StringBuilder clear = new StringBuilder();
            gs.access(chars -> clear.append(chars));
            try {
                client.updateUserPassword(userId, clear.toString(), false);
                LOG.ok("Password updated for user {0}", userId);
            } finally {
                for (int i = 0; i < clear.length(); i++) clear.setCharAt(i, '\0');
            }
        }

        // Handle groups delta
        for (AttributeDelta delta : deltas) {
            if (!"groups".equalsIgnoreCase(delta.getName())) continue;

            List<Object> toReplace = delta.getValuesToReplace();
            if (toReplace != null) {
                Set<String> desired = extractGroupIds(toReplace);
                reconcileGroupMemberships(userId, desired);
                continue;
            }
            List<Object> toAdd = delta.getValuesToAdd();
            if (toAdd != null) {
                for (Object v : toAdd) {
                    String groupId = extractGroupId(v);
                    client.addUserToGroup(groupId, userId);
                    LOG.ok("User {0} added to group {1} (delta)", userId, groupId);
                }
            }
            List<Object> toRemove = delta.getValuesToRemove();
            if (toRemove != null) {
                for (Object v : toRemove) {
                    String groupId = extractGroupId(v);
                    try {
                        client.removeUserFromGroup(groupId, userId);
                        LOG.ok("User {0} removed from group {1} (delta)", userId, groupId);
                    } catch (UnknownUidException e) {
                        LOG.warn("Group-user association not found, skipping remove: group={0} user={1}", groupId, userId);
                    }
                }
            }
        }
    }

    private void updateDeltaGroup(String groupId, Set<AttributeDelta> deltas) {
        JsonObject current = client.getGroup(groupId);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("name", safeGetString(current, "name"));
        if (current.has("description") && !current.get("description").isJsonNull()) {
            payload.put("description", current.get("description").getAsString());
        }

        for (AttributeDelta delta : deltas) {
            String name = delta.getName();
            List<Object> values = delta.getValuesToReplace() != null ? delta.getValuesToReplace()
                    : (delta.getValuesToAdd() != null ? delta.getValuesToAdd() : Collections.emptyList());
            if (values.isEmpty()) continue;

            if (Name.NAME.equalsIgnoreCase(name)) {
                payload.put("name", values.get(0).toString());
            } else if ("description".equalsIgnoreCase(name)) {
                payload.put("description", values.get(0).toString());
            } else {
                LOG.warn("Ignoring unknown group attribute delta: {0}", name);
            }
        }
        client.updateGroup(groupId, payload);
        LOG.ok("Group {0} updated via delta", groupId);
    }

    // -----------------------------------------------------------------------
    // ConnectorObject builders
    // -----------------------------------------------------------------------

    private ConnectorObject buildUserConnectorObject(JsonObject userJson, boolean fetchGroups) {
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(ObjectClass.ACCOUNT);

        String id        = safeGetString(userJson, "id");
        String loginName = safeGetString(userJson, "loginName");
        builder.setUid(id);
        builder.setName(loginName);

        addStringAttrIfPresent(builder, "displayName",    userJson, "displayName");
        addStringAttrIfPresent(builder, "firstName",      userJson, "firstName");
        addStringAttrIfPresent(builder, "lastName",       userJson, "lastName");
        addStringAttrIfPresent(builder, "primaryEmail",   userJson, "primaryEmail");
        addStringAttrIfPresent(builder, "secondaryEmail", userJson, "secondaryEmail");
        addStringAttrIfPresent(builder, "source",         userJson, "source");

        if (userJson.has("department") && !userJson.get("department").isJsonNull()) {
            JsonObject dept = userJson.getAsJsonObject("department");
            String deptId = safeGetString(dept, "id");
            if (deptId != null) builder.addAttribute("departmentId", deptId);
        }

        boolean status = userJson.has("status") && userJson.get("status").getAsBoolean();
        builder.addAttribute(OperationalAttributes.ENABLE_NAME, status);

        if (fetchGroups) {
            try {
                List<JsonObject> groups   = client.getUserGroups(id);
                List<ConnectorObjectReference> refs = new ArrayList<>();
                for (JsonObject g : groups) {
                    String gid   = safeGetString(g, "id");
                    String gname = safeGetString(g, "name");
                    if (gid == null) continue;
                    ConnectorObjectBuilder cob = new ConnectorObjectBuilder();
                    cob.setObjectClass(new ObjectClass(GROUP_CLASS));
                    cob.setUid(gid);
                    cob.setName(gname != null ? gname : gid);
                    refs.add(new ConnectorObjectReference(cob.build()));
                }
                if (!refs.isEmpty()) {
                    builder.addAttribute("groups", refs.toArray());
                }
            } catch (Exception e) {
                LOG.warn("Failed to fetch group memberships for user {0}: {1}", id, e.getMessage());
            }
        }

        return builder.build();
    }

    private ConnectorObject buildGroupConnectorObject(JsonObject groupJson, boolean fetchMembers) {
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(new ObjectClass(GROUP_CLASS));

        String gid  = safeGetString(groupJson, "id");
        String name = safeGetString(groupJson, "name");
        builder.setUid(gid);
        builder.setName(name);

        addStringAttrIfPresent(builder, "description", groupJson, "description");
        addStringAttrIfPresent(builder, "source",      groupJson, "source");

        if (groupJson.has("isDynamicGroup") && !groupJson.get("isDynamicGroup").isJsonNull()) {
            builder.addAttribute("isDynamicGroup", groupJson.get("isDynamicGroup").getAsBoolean());
        }

        if (fetchMembers) {
            try {
                List<JsonObject> members = client.getGroupMembers(gid);
                List<String> memberIds = new ArrayList<>();
                for (JsonObject m : members) {
                    String mid = safeGetString(m, "id");
                    if (mid != null) memberIds.add(mid);
                }
                if (!memberIds.isEmpty()) {
                    builder.addAttribute("members", memberIds.toArray());
                }
            } catch (Exception e) {
                LOG.warn("Failed to fetch members for group {0}: {1}", gid, e.getMessage());
            }
        }

        return builder.build();
    }

    // -----------------------------------------------------------------------
    // User payload builders
    // -----------------------------------------------------------------------

    /**
     * Builds a full user PUT/POST payload.
     *
     * @param accessor incoming attribute set
     * @param current  current server state (may be {@code null} for create)
     */
    private Map<String, Object> buildUserPayload(AttributesAccessor accessor, JsonObject current) {
        Map<String, Object> payload = new LinkedHashMap<>();

        // loginName - required
        String loginName = accessor.findString(Name.NAME);
        if (loginName != null) {
            payload.put("loginName", loginName);
        } else if (current != null) {
            payload.put("loginName", safeGetString(current, "loginName"));
        } else {
            throw new ConnectorException("loginName (__NAME__) is required for create");
        }

        // displayName - required; falls back to loginName on create if not provided
        String displayName = accessor.findString("displayName");
        if (displayName != null) {
            payload.put("displayName", displayName);
        } else if (current != null) {
            payload.put("displayName", safeGetString(current, "displayName"));
        } else {
            payload.put("displayName", payload.get("loginName"));
        }

        // primaryEmail - required
        String primaryEmail = accessor.findString("primaryEmail");
        if (primaryEmail != null) {
            payload.put("primaryEmail", primaryEmail);
        } else if (current != null) {
            payload.put("primaryEmail", safeGetString(current, "primaryEmail"));
        } else {
            throw new ConnectorException("primaryEmail is required for create");
        }

        // status (__ENABLE__) - required
        Boolean status = accessor.findBoolean(OperationalAttributes.ENABLE_NAME);
        if (status != null) {
            payload.put("status", status);
        } else if (current != null) {
            payload.put("status", current.has("status") && current.get("status").getAsBoolean());
        } else {
            payload.put("status", true);  // default to enabled on create
        }

        // Optional fields - use incoming value, then current value
        mergeOptionalString(payload, accessor, current, "firstName",      "firstName");
        mergeOptionalString(payload, accessor, current, "lastName",       "lastName");
        mergeOptionalString(payload, accessor, current, "secondaryEmail", "secondaryEmail");

        // departmentId maps to nested department.id
        String departmentId = accessor.findString("departmentId");
        if (departmentId != null) {
            Map<String, String> dept = new LinkedHashMap<>();
            dept.put("id", departmentId);
            payload.put("department", dept);
        } else if (current != null && current.has("department") && !current.get("department").isJsonNull()) {
            JsonObject dept = current.getAsJsonObject("department");
            String did = safeGetString(dept, "id");
            if (did != null) {
                Map<String, String> deptMap = new LinkedHashMap<>();
                deptMap.put("id", did);
                payload.put("department", deptMap);
            }
        }

        return payload;
    }

    /**
     * Builds a user payload pre-populated entirely from the current server state,
     * ready for delta updates to overwrite specific fields.
     */
    private Map<String, Object> buildCurrentUserPayload(JsonObject current) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("loginName",    safeGetString(current, "loginName"));
        payload.put("displayName",  safeGetString(current, "displayName"));
        payload.put("primaryEmail", safeGetString(current, "primaryEmail"));
        payload.put("status", current.has("status") && current.get("status").getAsBoolean());

        if (current.has("firstName")      && !current.get("firstName").isJsonNull())
            payload.put("firstName",      current.get("firstName").getAsString());
        if (current.has("lastName")       && !current.get("lastName").isJsonNull())
            payload.put("lastName",       current.get("lastName").getAsString());
        if (current.has("secondaryEmail") && !current.get("secondaryEmail").isJsonNull())
            payload.put("secondaryEmail", current.get("secondaryEmail").getAsString());
        if (current.has("department") && !current.get("department").isJsonNull()) {
            JsonObject dept = current.getAsJsonObject("department");
            String did = safeGetString(dept, "id");
            if (did != null) {
                Map<String, String> deptMap = new LinkedHashMap<>();
                deptMap.put("id", did);
                payload.put("department", deptMap);
            }
        }
        return payload;
    }

    private void mergeOptionalString(Map<String, Object> payload,
                                     AttributesAccessor accessor,
                                     JsonObject current,
                                     String connIdName,
                                     String jsonKey) {
        String val = accessor.findString(connIdName);
        if (val != null) {
            payload.put(jsonKey, val);
        } else if (current != null && current.has(jsonKey) && !current.get(jsonKey).isJsonNull()) {
            payload.put(jsonKey, current.get(jsonKey).getAsString());
        }
    }

    // -----------------------------------------------------------------------
    // Group membership reconciliation
    // -----------------------------------------------------------------------

    /**
     * Computes the diff between the current group memberships and the desired
     * set, then applies the minimum number of API calls to converge.
     */
    private void reconcileGroupMemberships(String userId, Set<String> desiredGroupIds) {
        List<JsonObject> currentGroups = client.getUserGroups(userId);
        Set<String> currentGroupIds = new HashSet<>();
        for (JsonObject g : currentGroups) {
            String gid = safeGetString(g, "id");
            if (gid != null) currentGroupIds.add(gid);
        }

        // Add missing
        for (String gid : desiredGroupIds) {
            if (!currentGroupIds.contains(gid)) {
                client.addUserToGroup(gid, userId);
                LOG.ok("User {0} added to group {1}", userId, gid);
            }
        }
        // Remove extra
        for (String gid : currentGroupIds) {
            if (!desiredGroupIds.contains(gid)) {
                try {
                    client.removeUserFromGroup(gid, userId);
                    LOG.ok("User {0} removed from group {1}", userId, gid);
                } catch (UnknownUidException e) {
                    LOG.warn("Membership not found, skipping remove: group={0} user={1}", gid, userId);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Helper utilities
    // -----------------------------------------------------------------------

    /** Extracts the group system ID from a {@link ConnectorObjectReference}. */
    private String extractGroupId(Object value) {
        ConnectorObjectReference ref = (ConnectorObjectReference) value;
        BaseConnectorObject obj = ref.getValue();
        Attribute uidAttr = null, nameAttr = null;
        for (Attribute attr : obj.getAttributes()) {
            if (Uid.NAME.equals(attr.getName())) uidAttr = attr;
            else if (Name.NAME.equals(attr.getName())) nameAttr = attr;
        }
        if (uidAttr != null && !uidAttr.getValue().isEmpty()) {
            return uidAttr.getValue().get(0).toString();
        }
        if (nameAttr != null && !nameAttr.getValue().isEmpty()) {
            return nameAttr.getValue().get(0).toString();
        }
        throw new ConnectorException("Cannot extract group ID from ConnectorObjectReference");
    }

    private Set<String> extractGroupIds(List<Object> refs) {
        Set<String> ids = new HashSet<>();
        if (refs == null) return ids;
        for (Object v : refs) ids.add(extractGroupId(v));
        return ids;
    }

    /** Safely extracts a String value from a JsonObject, returning {@code null} if absent or null. */
    private String safeGetString(JsonObject obj, String key) {
        if (obj.has(key) && !obj.get(key).isJsonNull()) return obj.get(key).getAsString();
        return null;
    }

    private void addStringAttrIfPresent(ConnectorObjectBuilder builder,
                                         String attrName, JsonObject json, String jsonKey) {
        String val = safeGetString(json, jsonKey);
        if (val != null) builder.addAttribute(attrName, val);
    }
}
