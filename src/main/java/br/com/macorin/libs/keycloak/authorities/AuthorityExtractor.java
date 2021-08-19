package br.com.macorin.libs.keycloak.authorities;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class AuthorityExtractor {

    private ObjectMapper objectMapper = new ObjectMapper();
    private String prefix;
    private Boolean authorityUpperCase;

    private static final String DEFAULT_PREFIX = "ROLE";
    private static final boolean DEFAULT_AUTHORITY_UPPER_CASE = true;

    public AuthorityExtractor() {
        this(DEFAULT_PREFIX, DEFAULT_AUTHORITY_UPPER_CASE);
    }

    public AuthorityExtractor(String prefix) {
        this(prefix, DEFAULT_AUTHORITY_UPPER_CASE);
    }

    public AuthorityExtractor(boolean authorityUpperCase) {
        this(DEFAULT_PREFIX, authorityUpperCase);
    }

    public AuthorityExtractor(String prefix, boolean authorityUpperCase) {
        this.prefix = prefix;
        this.authorityUpperCase = authorityUpperCase;
    }

    public Set<String> realmAccess(Map<String, Object> claims) {
        Set<String> rolesWithPrefix = new HashSet<>();
        JsonNode json = objectMapper.convertValue(claims, JsonNode.class);
        json.elements().forEachRemaining(
                e -> e.elements().forEachRemaining(r -> rolesWithPrefix.add(createRole(r.asText()))));
        return rolesWithPrefix;
    }

    public Set<String> resourceAccess(Map<String, Object> claims) {
        Set<String> rolesWithPrefix = new HashSet<>();
        Map<String, JsonNode> map = objectMapper.convertValue(claims, new TypeReference<Map<String, JsonNode>>(){});
        for (Map.Entry<String, JsonNode> jsonNode : map.entrySet()) {
            jsonNode
                    .getValue()
                    .elements()
                    .forEachRemaining(e -> e
                            .elements()
                            .forEachRemaining(r -> rolesWithPrefix.add(createRole(jsonNode.getKey(), r.asText()))));
        }
        return rolesWithPrefix;
    }

    private String createRole(String... values) {
        StringBuilder role = new StringBuilder(this.prefix);
        for (String value : values) {
            role.append("_").append(this.authorityUpperCase ? value.toUpperCase() : value);
        }
        return role.toString();
    }
}
