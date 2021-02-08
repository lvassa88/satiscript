package com.vassa.security;

import org.apache.http.client.methods.HttpRequestBase;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

public class RequestSigner {

    private static final String SIGNATURE_ALGORITHM = "rsa-sha256";

    private static final Map<String, List<String>> REQUIRED_HEADERS;
    static {
        REQUIRED_HEADERS = new HashMap<>();
        REQUIRED_HEADERS.put("get", Arrays.asList("(request-target)"));
        REQUIRED_HEADERS.put("post", Arrays.asList("(request-target)"));
        REQUIRED_HEADERS.put("put", Arrays.asList("(request-target)"));
        REQUIRED_HEADERS.put("delete", Arrays.asList("(request-target)"));
    }
    private final Signer signer;

    public RequestSigner(String keyId, Key privateKey, String method) {
        this.signer = buildSigner(keyId, privateKey, method);
    }

    protected Signer buildSigner(String keyId, Key privateKey, String method) {
        final SignatureAuth signatureAuth = new SignatureAuth(keyId, SIGNATURE_ALGORITHM, REQUIRED_HEADERS.get(method.toLowerCase()));
        return new Signer(privateKey, signatureAuth);
    }

    private List<String> lowercase(final List<String> headers) {
        final List<String> list = new ArrayList<>(headers.size());
        for (final String header : headers) {
            list.add(header.toLowerCase());
        }
        return list;
    }

    public void signRequest(HttpRequestBase request) {
        final String method = request.getMethod().toLowerCase();
        // nothing to sign for options
        if (method.equals("options")) {
            return;
        }

        final String path = extractPath(request.getURI());

        if (!request.containsHeader("Date")) {
            Instant now = Instant.now();
            request.addHeader("Date", now.toString());
        }

        if (!request.containsHeader("Digest")) {
            request.addHeader("Digest", generateDigest(""));
        }

        final Map<String, String> headers = extractHeadersToSign(request);
        final String signature = this.calculateSignature(method, path, headers);
        //System.out.println("Signature: " + signature);
        request.setHeader("Authorization", signature);
    }

    private String generateDigest(final String msg) {
        String digestStr = "";
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(msg.getBytes(StandardCharsets.UTF_8));
            digestStr = new String(digest);
        } catch (NoSuchAlgorithmException e ) {
            System.err.println("Cannot find Algorithm: " + e);
        }
        return digestStr;
    }

    private static String extractPath(URI uri) {
        String path = uri.getRawPath();
        String query = uri.getRawQuery();
        if (query != null && !query.trim().isEmpty()) {
            path = path + "?" + query;
        }
        return path;
    }

    private static Map<String, String> extractHeadersToSign(HttpRequestBase request) {
        List<String> headersToSign = REQUIRED_HEADERS.get(request.getMethod().toLowerCase());
        if (headersToSign == null) {
            throw new RuntimeException("Don't know how to sign method " + request.getMethod());
        }
        return headersToSign.stream()
                // (request-target) is a pseudo-header
                .filter(header -> !header.toLowerCase().equals("(request-target)"))
                .collect(Collectors.toMap(
                        header -> header,
                        header -> {
                            if (!request.containsHeader(header)) {
                                throw new RuntimeException("Missing required headers: " + header);
                            }
                            if (request.getHeaders(header).length > 1) {
                                throw new RuntimeException(
                                        String.format("Expected one value for header %s", header));
                            }
                            return request.getFirstHeader(header).getValue();
                        }));
    }

    private String calculateSignature(String method, String path, Map<String, String> headers) {
        try {
            return signer.sign(method, path, headers).toString();
        } catch (IOException e) {
            throw new RuntimeException("Failed to generate signature", e);
        }
    }

}
