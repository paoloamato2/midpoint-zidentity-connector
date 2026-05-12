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

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.junit.jupiter.api.*;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration-style unit tests for {@link ZIdentityClient} using OkHttp's
 * {@link MockWebServer}. No real network connections are made.
 */
class ZIdentityClientTest {

    private MockWebServer mockWebServer;
    private ZIdentityConfiguration config;

    // Token endpoint responds with this payload
    private static final String TOKEN_RESPONSE =
            "{\"access_token\":\"test-token\",\"expires_in\":3600}";

    @BeforeEach
    void setUp() throws IOException {
        mockWebServer = new MockWebServer();
        mockWebServer.start();

        String baseUrl = mockWebServer.url("").toString().replaceAll("/$", "");

        config = new ZIdentityConfiguration() {
            @Override
            public String getTokenUrl() {
                return baseUrl + "/oauth2/v1/token";
            }

            @Override
            public String getApiBaseUrl() {
                return baseUrl + "/ziam/admin/api/v1";
            }
        };
        config.setTenant("acme");
        config.setClientId("client-id");
        config.setClientSecret(new GuardedString("secret".toCharArray()));
        config.setSslVerify(true);
    }

    @AfterEach
    void tearDown() throws IOException {
        mockWebServer.shutdown();
    }

    // ------------------------------------------------------------------
    // OAuth token acquisition
    // ------------------------------------------------------------------

    @Test
    @DisplayName("getAccessToken() posts client_credentials and returns bearer token")
    void getAccessToken_returnsTokenFromServer() {
        mockWebServer.enqueue(new MockResponse()
                .setBody(TOKEN_RESPONSE)
                .addHeader("Content-Type", "application/json"));

        ZIdentityClient client = new ZIdentityClient(config);
        String token = client.getAccessToken();

        assertEquals("test-token", token);
    }

    @Test
    @DisplayName("getAccessToken() uses cached token on second call")
    void getAccessToken_usesCachedToken() {
        // Only one token response is queued; second call must reuse it
        mockWebServer.enqueue(new MockResponse()
                .setBody(TOKEN_RESPONSE)
                .addHeader("Content-Type", "application/json"));

        ZIdentityClient client = new ZIdentityClient(config);
        client.getAccessToken();
        client.getAccessToken(); // must not hit the server again

        assertEquals(1, mockWebServer.getRequestCount());
    }

    @Test
    @DisplayName("getAccessToken() throws ConnectorException when token endpoint fails")
    void getAccessToken_serverError_throwsConnectorException() {
        mockWebServer.enqueue(new MockResponse().setResponseCode(500).setBody("Internal Server Error"));

        ZIdentityClient client = new ZIdentityClient(config);
        assertThrows(ConnectorException.class, client::getAccessToken);
    }

    // ------------------------------------------------------------------
    // testConnection()
    // ------------------------------------------------------------------

    @Test
    @DisplayName("testConnection() succeeds when API returns 200 with empty record set")
    void testConnection_success() {
        enqueueToken();
        mockWebServer.enqueue(new MockResponse()
                .setBody("{\"records\":[]}")
                .addHeader("Content-Type", "application/json"));

        ZIdentityClient client = new ZIdentityClient(config);
        assertDoesNotThrow(client::testConnection);
    }

    @Test
    @DisplayName("testConnection() throws when API returns 401")
    void testConnection_unauthorized_throws() {
        enqueueToken();
        mockWebServer.enqueue(new MockResponse()
                .setResponseCode(401).setBody("{\"error\":\"unauthorized\"}"));

        ZIdentityClient client = new ZIdentityClient(config);
        assertThrows(ConnectorException.class, client::testConnection);
    }

    // ------------------------------------------------------------------
    // User operations
    // ------------------------------------------------------------------

    @Test
    @DisplayName("getUser() returns parsed JsonObject for a valid user ID")
    void getUser_returnsUser() {
        enqueueToken();
        mockWebServer.enqueue(new MockResponse()
                .setBody("{\"id\":\"u1\",\"loginName\":\"alice@example.com\"}")
                .addHeader("Content-Type", "application/json"));

        ZIdentityClient client = new ZIdentityClient(config);
        var user = client.getUser("u1");

        assertEquals("u1", user.get("id").getAsString());
        assertEquals("alice@example.com", user.get("loginName").getAsString());
    }

    @Test
    @DisplayName("getUser() throws UnknownUidException when server returns 404")
    void getUser_notFound_throwsUnknownUidException() {
        enqueueToken();
        mockWebServer.enqueue(new MockResponse().setResponseCode(404));

        ZIdentityClient client = new ZIdentityClient(config);
        assertThrows(UnknownUidException.class, () -> client.getUser("nonexistent"));
    }

    @Test
    @DisplayName("createUser() posts payload and returns the new user ID")
    void createUser_returnsNewUserId() throws InterruptedException {
        enqueueToken();
        mockWebServer.enqueue(new MockResponse()
                .setBody("{\"id\":\"new-uid\"}")
                .addHeader("Content-Type", "application/json"));

        Map<String, Object> payload = new HashMap<>();
        payload.put("loginName", "bob@example.com");
        payload.put("displayName", "Bob");
        payload.put("primaryEmail", "bob@example.com");
        payload.put("status", true);

        ZIdentityClient client = new ZIdentityClient(config);
        String uid = client.createUser(payload);

        assertEquals("new-uid", uid);
        RecordedRequest req = mockWebServer.takeRequest(); // token
        RecordedRequest createReq = mockWebServer.takeRequest(); // POST /users
        assertEquals("POST", createReq.getMethod());
        assertTrue(createReq.getPath().endsWith("/users"));
    }

    @Test
    @DisplayName("createUser() throws AlreadyExistsException when server returns 409")
    void createUser_conflict_throwsAlreadyExistsException() {
        enqueueToken();
        mockWebServer.enqueue(new MockResponse().setResponseCode(409).setBody("{\"error\":\"conflict\"}"));

        ZIdentityClient client = new ZIdentityClient(config);
        assertThrows(AlreadyExistsException.class, () -> client.createUser(Collections.emptyMap()));
    }

    @Test
    @DisplayName("deleteUser() sends DELETE request to correct endpoint")
    void deleteUser_sendsDeleteRequest() throws InterruptedException {
        enqueueToken();
        mockWebServer.enqueue(new MockResponse().setResponseCode(204));

        ZIdentityClient client = new ZIdentityClient(config);
        assertDoesNotThrow(() -> client.deleteUser("u42"));

        mockWebServer.takeRequest(); // token
        RecordedRequest deleteReq = mockWebServer.takeRequest();
        assertEquals("DELETE", deleteReq.getMethod());
        assertTrue(deleteReq.getPath().endsWith("/users/u42"));
    }

    // ------------------------------------------------------------------
    // Group operations
    // ------------------------------------------------------------------

    @Test
    @DisplayName("createGroup() posts payload and returns the new group ID")
    void createGroup_returnsNewGroupId() {
        enqueueToken();
        mockWebServer.enqueue(new MockResponse()
                .setBody("{\"id\":\"g99\"}")
                .addHeader("Content-Type", "application/json"));

        Map<String, Object> payload = new HashMap<>();
        payload.put("name", "Engineering");

        ZIdentityClient client = new ZIdentityClient(config);
        assertEquals("g99", client.createGroup(payload));
    }

    @Test
    @DisplayName("listUsersPage() returns parsed list from records array")
    void listUsersPage_returnsRecords() {
        enqueueToken();
        mockWebServer.enqueue(new MockResponse()
                .setBody("{\"records\":[{\"id\":\"u1\"},{\"id\":\"u2\"}]}")
                .addHeader("Content-Type", "application/json"));

        ZIdentityClient client = new ZIdentityClient(config);
        List<com.google.gson.JsonObject> records = client.listUsersPage(0, 10, null);

        assertEquals(2, records.size());
        assertEquals("u1", records.get(0).get("id").getAsString());
    }

    @Test
    @DisplayName("addUserToGroup() sends POST to correct group membership endpoint")
    void addUserToGroup_sendsCorrectRequest() throws InterruptedException {
        enqueueToken();
        mockWebServer.enqueue(new MockResponse().setResponseCode(200).setBody("{}"));

        ZIdentityClient client = new ZIdentityClient(config);
        client.addUserToGroup("g1", "u1");

        mockWebServer.takeRequest(); // token
        RecordedRequest req = mockWebServer.takeRequest();
        assertEquals("POST", req.getMethod());
        assertTrue(req.getPath().endsWith("/groups/g1/users/u1"));
    }

    @Test
    @DisplayName("removeUserFromGroup() sends DELETE to correct group membership endpoint")
    void removeUserFromGroup_sendsCorrectRequest() throws InterruptedException {
        enqueueToken();
        mockWebServer.enqueue(new MockResponse().setResponseCode(204));

        ZIdentityClient client = new ZIdentityClient(config);
        client.removeUserFromGroup("g1", "u1");

        mockWebServer.takeRequest(); // token
        RecordedRequest req = mockWebServer.takeRequest();
        assertEquals("DELETE", req.getMethod());
        assertTrue(req.getPath().endsWith("/groups/g1/users/u1"));
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    private void enqueueToken() {
        mockWebServer.enqueue(new MockResponse()
                .setBody(TOKEN_RESPONSE)
                .addHeader("Content-Type", "application/json"));
    }
}
