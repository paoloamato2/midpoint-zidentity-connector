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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import okhttp3.FormBody;
import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.Uid;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * HTTP client for the Zscaler ZIdentity Admin API.
 * <p>
 * Handles OAuth 2.0 {@code client_credentials} token acquisition and automatic
 * refresh, pagination for list endpoints, and all CRUD operations for Users,
 * Groups, and group memberships.
 * <p>
 * All API calls target: {@code https://api.zsapi.net/ziam/admin/api/v1}
 * Token endpoint: {@code https://<tenant>.zslogin.net/oauth2/v1/token}
 */
public class ZIdentityClient {

    private static final Log LOG = Log.getLog(ZIdentityClient.class);

    private static final MediaType JSON_MEDIA = MediaType.parse("application/json; charset=utf-8");

    /** Refresh the token this many ms before its actual expiry. */
    private static final long TOKEN_EXPIRY_BUFFER_MS = 30_000L;

    private final ZIdentityConfiguration config;
    private final OkHttpClient http;
    private final Gson gson;

    // Token cache — guarded by tokenLock
    private volatile String accessToken;
    private volatile long   tokenExpiresAt; // epoch milliseconds
    private final ReentrantLock tokenLock = new ReentrantLock();

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    public ZIdentityClient(ZIdentityConfiguration config) {
        this.config = config;
        this.gson   = new GsonBuilder().create();
        this.http   = buildHttpClient();
    }

    // -----------------------------------------------------------------------
    // OkHttp client factory
    // -----------------------------------------------------------------------

    private OkHttpClient buildHttpClient() {
        OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS);

        if (!config.isSslVerify()) {
            LOG.warn("SSL certificate verification is DISABLED — use only in non-production environments");
            try {
                TrustManager[] trustAll = new TrustManager[]{
                    new X509TrustManager() {
                        public void checkClientTrusted(X509Certificate[] c, String a) {}
                        public void checkServerTrusted(X509Certificate[] c, String a) {}
                        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    }
                };
                SSLContext sslCtx = SSLContext.getInstance("TLS");
                sslCtx.init(null, trustAll, new SecureRandom());
                builder.sslSocketFactory(sslCtx.getSocketFactory(), (X509TrustManager) trustAll[0])
                       .hostnameVerifier((host, session) -> true);
            } catch (Exception e) {
                throw new ConnectorException("Failed to configure SSL bypass", e);
            }
        }
        return builder.build();
    }

    // -----------------------------------------------------------------------
    // OAuth 2.0 token management
    // -----------------------------------------------------------------------

    String getAccessToken() {
        // Fast path: token still valid
        if (accessToken != null && System.currentTimeMillis() < tokenExpiresAt - TOKEN_EXPIRY_BUFFER_MS) {
            return accessToken;
        }
        tokenLock.lock();
        try {
            // Double-check after acquiring lock
            if (accessToken != null && System.currentTimeMillis() < tokenExpiresAt - TOKEN_EXPIRY_BUFFER_MS) {
                return accessToken;
            }
            fetchNewToken();
            return accessToken;
        } finally {
            tokenLock.unlock();
        }
    }

    private void fetchNewToken() {
        LOG.ok("Fetching new ZIdentity OAuth2 access token from {0}", config.getTokenUrl());

        // Extract client secret into a StringBuilder, then wipe it after use
        final StringBuilder secret = new StringBuilder();
        config.getClientSecret().access(chars -> secret.append(chars));

        RequestBody body = new FormBody.Builder()
                .add("grant_type",    "client_credentials")
                .add("client_id",     config.getClientId())
                .add("client_secret", secret.toString())
                .build();

        // Wipe secret from memory
        for (int i = 0; i < secret.length(); i++) secret.setCharAt(i, '\0');

        Request request = new Request.Builder()
                .url(config.getTokenUrl())
                .post(body)
                .header("Accept", "application/json")
                .build();

        try (Response response = http.newCall(request).execute()) {
            String responseBody = response.body() != null ? response.body().string() : "";
            if (!response.isSuccessful()) {
                throw new ConnectorException(
                        "Failed to obtain OAuth2 access token: HTTP " + response.code() + " — " + responseBody);
            }
            JsonObject json      = JsonParser.parseString(responseBody).getAsJsonObject();
            this.accessToken     = json.get("access_token").getAsString();
            long expiresIn       = json.has("expires_in") ? json.get("expires_in").getAsLong() : 3600L;
            this.tokenExpiresAt  = System.currentTimeMillis() + expiresIn * 1000L;
            LOG.ok("Access token acquired, expires in {0} seconds", expiresIn);
        } catch (ConnectorException e) {
            throw e;
        } catch (IOException e) {
            throw new ConnectorException("Network error while fetching OAuth2 token", e);
        }
    }

    // -----------------------------------------------------------------------
    // Generic HTTP helpers
    // -----------------------------------------------------------------------

    private String apiUrl(String path) {
        return config.getApiBaseUrl() + "/" + path.replaceFirst("^/+", "");
    }

    /** HTTP GET with optional query parameters. */
    JsonElement doGet(String path, Map<String, String> params) {
        HttpUrl.Builder urlBuilder = HttpUrl.parse(apiUrl(path)).newBuilder();
        if (params != null) params.forEach(urlBuilder::addQueryParameter);

        Request req = new Request.Builder()
                .url(urlBuilder.build())
                .get()
                .header("Authorization", "Bearer " + getAccessToken())
                .header("Accept", "application/json")
                .build();
        return execute(req);
    }

    /** HTTP POST with an optional JSON body. */
    JsonElement doPost(String path, Object payload) {
        String json = payload != null ? gson.toJson(payload) : "{}";
        RequestBody body = RequestBody.create(json, JSON_MEDIA);
        Request req = new Request.Builder()
                .url(apiUrl(path))
                .post(body)
                .header("Authorization", "Bearer " + getAccessToken())
                .header("Accept", "application/json")
                .build();
        return execute(req);
    }

    /** HTTP PUT with a JSON body. */
    JsonElement doPut(String path, Object payload) {
        String json = gson.toJson(payload);
        RequestBody body = RequestBody.create(json, JSON_MEDIA);
        Request req = new Request.Builder()
                .url(apiUrl(path))
                .put(body)
                .header("Authorization", "Bearer " + getAccessToken())
                .header("Accept", "application/json")
                .build();
        return execute(req);
    }

    /** HTTP DELETE (no body, no response body expected). */
    void doDelete(String path) {
        Request req = new Request.Builder()
                .url(apiUrl(path))
                .delete()
                .header("Authorization", "Bearer " + getAccessToken())
                .header("Accept", "application/json")
                .build();
        executeVoid(req);
    }

    private JsonElement execute(Request req) {
        try (Response response = http.newCall(req).execute()) {
            String responseBody = response.body() != null ? response.body().string() : "";
            handleErrorResponse(response.code(), responseBody, req.url().toString());
            if (responseBody.isEmpty()) return JsonNull.INSTANCE;
            return JsonParser.parseString(responseBody);
        } catch (ConnectorException e) {
            throw e;
        } catch (IOException e) {
            throw new ConnectorException("Network error calling " + req.url(), e);
        }
    }

    private void executeVoid(Request req) {
        try (Response response = http.newCall(req).execute()) {
            String responseBody = response.body() != null ? response.body().string() : "";
            handleErrorResponse(response.code(), responseBody, req.url().toString());
        } catch (ConnectorException e) {
            throw e;
        } catch (IOException e) {
            throw new ConnectorException("Network error calling " + req.url(), e);
        }
    }

    private void handleErrorResponse(int code, String body, String url) {
        if (code >= 200 && code < 300) return;
        if (code == 404) {
            throw new UnknownUidException("Resource not found at: " + url);
        }
        if (code == 409) {
            throw new AlreadyExistsException("Resource already exists: " + url + " — " + body);
        }
        if (code == 401 || code == 403) {
            // Invalidate cached token so the next call re-authenticates
            accessToken = null;
            throw new ConnectorException("Authentication/Authorization error HTTP " + code + " — " + body);
        }
        throw new ConnectorException("ZIdentity API error HTTP " + code + " — " + body);
    }

    // -----------------------------------------------------------------------
    // Pagination helper
    // -----------------------------------------------------------------------

    /**
     * Fetches a single page from a paginated endpoint and returns the
     * {@code records} array as a list of {@link JsonObject}.
     */
    List<JsonObject> fetchPage(String path, int offset, int limit, Map<String, String> extraParams) {
        Map<String, String> params = new HashMap<>(extraParams != null ? extraParams : Collections.emptyMap());
        params.put("offset", String.valueOf(offset));
        params.put("limit",  String.valueOf(limit));
        JsonElement element = doGet(path, params);
        return extractRecords(element);
    }

    private List<JsonObject> extractRecords(JsonElement element) {
        List<JsonObject> result = new ArrayList<>();
        if (element == null || element.isJsonNull()) return result;

        // Some endpoints wrap the page object in a one-element JSON array
        JsonObject page;
        if (element.isJsonArray()) {
            JsonArray arr = element.getAsJsonArray();
            if (arr.size() == 0) return result;
            page = arr.get(0).getAsJsonObject();
        } else {
            page = element.getAsJsonObject();
        }
        JsonArray records = page.has("records") ? page.getAsJsonArray("records") : new JsonArray();
        for (JsonElement rec : records) {
            if (rec.isJsonObject()) result.add(rec.getAsJsonObject());
        }
        return result;
    }

    // -----------------------------------------------------------------------
    // User operations
    // -----------------------------------------------------------------------

    /**
     * Fetches one page of users. Callers stream pages to avoid holding all
     * users in memory simultaneously.
     *
     * @param offset      pagination offset
     * @param limit       page size
     * @param extraParams additional query parameters (e.g. loginname filter)
     */
    public List<JsonObject> listUsersPage(int offset, int limit, Map<String, String> extraParams) {
        return fetchPage("users", offset, limit, extraParams);
    }

    /** Retrieves a single user by system ID. Throws {@link UnknownUidException} if not found. */
    public JsonObject getUser(String userId) {
        return doGet("users/" + userId, null).getAsJsonObject();
    }

    /**
     * Creates a new user and returns the system-assigned user ID.
     * Required fields in payload: {@code loginName}, {@code displayName},
     * {@code primaryEmail}, {@code status}.
     */
    public String createUser(Map<String, Object> payload) {
        JsonElement response = doPost("users", payload);
        return response.getAsJsonObject().get("id").getAsString();
    }

    /**
     * Replaces all writable fields for the given user (full PUT).
     * Required fields: {@code loginName}, {@code displayName},
     * {@code primaryEmail}, {@code status}.
     */
    public void updateUser(String userId, Map<String, Object> payload) {
        doPut("users/" + userId, payload);
    }

    /** Permanently deletes a user. Throws {@link UnknownUidException} if not found. */
    public void deleteUser(String userId) {
        doDelete("users/" + userId);
    }

    /** Sends a password-reset email to the user. */
    public void resetUserPassword(String userId) {
        doPost("users/" + userId + ":resetpassword", null);
    }

    /**
     * Sets a new password directly for the user.
     *
     * @param resetOnLogin when {@code true} the user must change password on next login
     */
    public void updateUserPassword(String userId, String newPassword, boolean resetOnLogin) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("password",       newPassword);
        payload.put("resetPwdOnLogin", resetOnLogin);
        doPut("users/" + userId + ":updatepassword", payload);
    }

    /**
     * Returns all groups the user belongs to (full list, all pages).
     * Each entry is a full group JSON object with at least {@code id} and {@code name}.
     */
    public List<JsonObject> getUserGroups(String userId) {
        List<JsonObject> all = new ArrayList<>();
        int offset = 0;
        int limit  = config.getPageSize();
        while (true) {
            List<JsonObject> page = fetchPage("users/" + userId + "/groups", offset, limit, null);
            all.addAll(page);
            if (page.size() < limit) break;
            offset += limit;
        }
        return all;
    }

    // -----------------------------------------------------------------------
    // Group operations
    // -----------------------------------------------------------------------

    /**
     * Fetches one page of groups.
     *
     * @param offset      pagination offset
     * @param limit       page size
     * @param extraParams additional query parameters (e.g. name[like] filter)
     */
    public List<JsonObject> listGroupsPage(int offset, int limit, Map<String, String> extraParams) {
        return fetchPage("groups", offset, limit, extraParams);
    }

    /** Retrieves a single group by system ID. Throws {@link UnknownUidException} if not found. */
    public JsonObject getGroup(String groupId) {
        return doGet("groups/" + groupId, null).getAsJsonObject();
    }

    /**
     * Creates a new group and returns the system-assigned group ID.
     * Required field in payload: {@code name}.
     */
    public String createGroup(Map<String, Object> payload) {
        JsonElement response = doPost("groups", payload);
        return response.getAsJsonObject().get("id").getAsString();
    }

    /**
     * Replaces all writable fields of the given group (full PUT).
     * Required field: {@code name}.
     */
    public void updateGroup(String groupId, Map<String, Object> payload) {
        doPut("groups/" + groupId, payload);
    }

    /** Permanently deletes a group. Throws {@link UnknownUidException} if not found. */
    public void deleteGroup(String groupId) {
        doDelete("groups/" + groupId);
    }

    /**
     * Returns all members (users) of a group (full list, all pages).
     * Each entry is a full user JSON object.
     */
    public List<JsonObject> getGroupMembers(String groupId) {
        List<JsonObject> all = new ArrayList<>();
        int offset = 0;
        int limit  = config.getPageSize();
        while (true) {
            List<JsonObject> page = fetchPage("groups/" + groupId + "/users", offset, limit, null);
            all.addAll(page);
            if (page.size() < limit) break;
            offset += limit;
        }
        return all;
    }

    // -----------------------------------------------------------------------
    // Group membership operations
    // -----------------------------------------------------------------------

    /** Adds a single user to a group. */
    public void addUserToGroup(String groupId, String userId) {
        doPost("groups/" + groupId + "/users/" + userId, null);
    }

    /** Removes a single user from a group. */
    public void removeUserFromGroup(String groupId, String userId) {
        doDelete("groups/" + groupId + "/users/" + userId);
    }

    // -----------------------------------------------------------------------
    // Connectivity test
    // -----------------------------------------------------------------------

    /**
     * Verifies that credentials are valid and the API is reachable by
     * issuing a minimal list-users request (limit=1).
     */
    public void testConnection() {
        LOG.ok("Testing ZIdentity connection to {0}", config.getApiBaseUrl());
        Map<String, String> params = new HashMap<>();
        params.put("offset", "0");
        params.put("limit",  "1");
        doGet("users", params);
        LOG.ok("ZIdentity connection test OK");
    }
}
