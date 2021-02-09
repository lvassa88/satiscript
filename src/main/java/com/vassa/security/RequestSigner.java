package com.vassa.security;

import org.apache.http.client.methods.HttpRequestBase;

import java.io.IOException;
import java.net.URI;
import java.security.Key;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class RequestSigner {

    private static final String SIGNATURE_ALGORITHM = "rsa-sha256";
    private static final List<String> REQUIRED_HEADERS = Arrays.asList("(request-target)", "date", "digest");

    private final Signer signer;

    public RequestSigner(String keyId, Key privateKey) {
        this.signer = buildSigner(keyId, privateKey);
    }

    protected Signer buildSigner(String keyId, Key privateKey) {
        final SignatureAuth signatureAuth = new SignatureAuth(keyId, SIGNATURE_ALGORITHM, REQUIRED_HEADERS);
        return new Signer(privateKey, signatureAuth);
    }

    public void signRequest(HttpRequestBase request) {
        final String method = request.getMethod().toLowerCase();
        final String path = extractPath(request.getURI());

        if (!request.containsHeader("Date")) {
            Instant now = Instant.now();
            request.addHeader("Date", now.toString());
        }

        final Map<String, String> headers = extractHeadersToSign(request);
        final String signature = this.calculateSignature(method, path, headers);
        //System.out.println("Signature: " + signature);
        request.setHeader("Authorization", signature);
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
        List<String> headersToSign = Arrays.asList(request.getAllHeaders()).stream().map(h -> h.getName()).collect(Collectors.toList());
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
