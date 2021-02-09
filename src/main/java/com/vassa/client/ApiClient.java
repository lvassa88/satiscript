package com.vassa.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.hash.Hashing;
import com.vassa.security.RequestSigner;
import com.vassa.util.PrivateKeyUtil;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.*;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.List;

public class ApiClient {

    public static final String AUTHENTICATION_KEY_ROLE_PUBLIC = "PUBLIC";
    public static final String FORBIDDEN_ERR_MESSAGE = "The signature string is malformed or the key-id is wrong";
    public static final String PUBLIC_ROLE_ERR_MESSAGE = "the key-id was recognized but the signature is wrong.";
    public static final String DIGEST = "digest";
    private final String endpoint;
    private final RequestSigner signer;

    public ApiClient(final String endpoint, final String keyId, final String pathFile)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        checkEndpoint(endpoint);
        checkKeyId(keyId);
        checkFileExists(pathFile);
        this.endpoint = endpoint;
        PrivateKey privateKey = PrivateKeyUtil.loadPrivateKey(pathFile);
        this.signer = new RequestSigner(keyId, privateKey);
    }

    private void checkKeyId(String keyId) {
        if(keyId == null || keyId.trim().equals("")) {
            throw new IllegalArgumentException("Key ID is not valid: [" + keyId + "]");
        }
    }

    private void checkFileExists(String pathFile) {
        File f = new File(pathFile);
        if(!f.exists()) {
            throw new IllegalArgumentException("Not found file in path: " + pathFile);
        }
    }

    private void checkEndpoint(final String endpoint) throws IOException {
        new URL(endpoint).openStream().close();
    }

    public void getMethod(String payload) {
        HttpRequestBase request = new HttpGet(endpoint);
        request.setHeader(DIGEST, generateDigest(payload));
        signer.signRequest(request);
        call(request);
    }

    public void postMethod(String payload) {
        HttpRequestBase request = new HttpPost(endpoint);
        request.setHeader(DIGEST, generateDigest(payload));
        request.setHeader("Content-Type", "application/json");
        ((HttpPost) request).setEntity(convert(payload));
        call(request);
    }

    public void putMethod(String payload) {
        HttpRequestBase request = new HttpPut(endpoint);
        request.setHeader(DIGEST, generateDigest(payload));
        request.setHeader("Content-Type", "application/json");
        ((HttpPut) request).setEntity(convert(payload));
        call(request);
    }

    public void deleteMethod(String payload) {
        HttpRequestBase request = new HttpDelete(endpoint);
        request.setHeader(DIGEST, generateDigest(payload));
        call(request);
    }

    private void call(final HttpRequestBase request) {
        signer.signRequest(request);
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
            HttpResponse response = httpClient.execute(request);
            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                String resp = parseHttpResponse(response);
                boolean isRolePublic = isAuthenticationRolePublic(resp);
                if(isRolePublic) {
                    System.out.println(String.format("%s - %s", HttpStatus.SC_OK, PUBLIC_ROLE_ERR_MESSAGE));
                } else {
                    ObjectMapper objMapper = new ObjectMapper();
                    String jsonResponse = objMapper.writerWithDefaultPrettyPrinter().writeValueAsString(resp);
                    System.out.println("Response : " + jsonResponse);
                }
            } else if(response.getStatusLine().getStatusCode() == HttpStatus.SC_FORBIDDEN) {
                System.out.println(String.format("%s - %s", HttpStatus.SC_FORBIDDEN, FORBIDDEN_ERR_MESSAGE));
            } else {
                System.out.println(String.format("Error response: %s", response.getStatusLine()));
            }
        } catch (IOException e) {
            throw new RuntimeException("Exception during call api: " + e);
        }
    }

    private StringEntity convert(String payload) {
        try {
            return new StringEntity(payload);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("Not supported payload: " + payload + "\n Error: " + e);
        }
    }

    private String generateDigest(final String msg) {
        return Hashing.sha256().hashString(msg, StandardCharsets.UTF_8).toString();
    }


    private boolean isAuthenticationRolePublic(final String resp) {
        List<String> attributeJson = Arrays.asList("authentication_key", "role");
        Object obj = new JSONObject(resp);
        for (String attribute: attributeJson) {
            if(obj instanceof JSONObject) {
                JSONObject jsonObj = (JSONObject) obj;
                obj = jsonObj.get(attribute);
            }
        }

        if(obj instanceof String) {
            String role = (String) obj;
            if(AUTHENTICATION_KEY_ROLE_PUBLIC.equalsIgnoreCase(role)) {
                return true;
            }
        }
        return false;
    }

    private String parseHttpResponse(HttpResponse response) {
        try {
            return EntityUtils.toString(response.getEntity());
        } catch (IOException e) {
            throw new RuntimeException("Error on parsing response: " + response);
        }
    }

}
