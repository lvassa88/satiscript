package com.vassa.security;

import java.util.*;
import java.util.stream.Collectors;

public class Signatures {

    public static String createSigningString(final List<String> required, String method, final String uri, Map<String, String> headers) {
        headers = lowercase(headers);

        final List<String> list = new ArrayList<>(required.size());

        for (final String key : required) {
            if ("(request-target)".equals(key)) {
                method = lowercase(method);
                String collect = Arrays.asList("(request-target):", method, uri).stream().collect(Collectors.joining(" "));
                list.add(collect);
            } else {
                final String value = headers.get(key);
                if (value == null) {
                    System.out.println("Missing required headers: " + key);
                    throw new RuntimeException("Missing required headers...");
                }

                list.add(key + ": " + value);
            }
        }

        return list.stream().collect(Collectors.joining("\n"));
    }

    private static Map<String, String> lowercase(final Map<String, String> headers) {
        final Map<String, String> map = new HashMap<>();
        for (final Map.Entry<String, String> entry : headers.entrySet()) {
            map.put(entry.getKey().toLowerCase(), entry.getValue());
        }
        return map;
    }

    private static String lowercase(final String spec) {
        return spec.toLowerCase();
    }
}

