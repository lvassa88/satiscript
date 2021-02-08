package com.vassa.security;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class SignatureAuth {

    private final String keyId;

    private final String algorithm;

    private final String signature;

    private final List<String> headers;

    public SignatureAuth(final String keyId,
                         final String algorithm,
                         final List<String> headers) {
        this(keyId, algorithm, null, headers);
    }

    public SignatureAuth(final String keyId,
                         final String algorithm,
                         final String signature,
                         final List<String> headers) {
        if (keyId == null || keyId.trim().isEmpty()) {
            throw new IllegalArgumentException("keyId is required.");
        }
        if (algorithm == null) {
            throw new IllegalArgumentException("algorithm is required.");
        }

        this.keyId = keyId;
        this.algorithm = algorithm;
        this.signature = signature;

        if (headers == null || headers.size() == 0) {
            final List<String> list = new ArrayList<>();
            System.out.println("Add empty list...");
            this.headers = Collections.unmodifiableList(list);
        } else {
            this.headers = Collections.unmodifiableList(lowercase(headers));
        }
    }

    public String getKeyId() {
        return keyId;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public List<String> getHeaders() {
        return headers;
    }

    private static String normalize(String authorization) {
        final String start = "signature ";

        final String prefix = authorization.substring(0, start.length()).toLowerCase();

        if (prefix.equals(start)) {
            authorization = authorization.substring(start.length());
        }
        return authorization.trim();
    }

    private List<String> lowercase(final List<String> headers) {
        final List<String> list = new ArrayList<>(headers.size());
        for (final String header : headers) {
            list.add(header.toLowerCase());
        }
        return list;
    }

    @Override
    public String toString() {
        final Object alg = algorithm;
        return "Signature " +
                "keyId=\"" + keyId + '\"' +
                ",algorithm=\"" + alg + '\"' +
                ",headers=\"" + headers.stream().collect(Collectors.joining(" ")) + '\"' +
                ",signature=\"" + signature + '\"';
    }
}
