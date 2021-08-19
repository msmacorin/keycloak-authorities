# Keycloak Authorities

Lib criada para extração das roles presentes do token JWT criado pelo Keycloak

### Utilização

Adicione a depedencia no pom do projeto

``` xml
<dependency>
    <groupId>br.com.macorin.libs</groupId>
    <artifactId>keycloak-authorities</artifactId>
    <version>${keycloak-authorities.version}</version>
</dependency>
```

Utilizando spring, para obter as authorities pode criar um component extendendo um Converter

``` java
import br.com.macorin.libs.keycloak.authorities.AuthorityExtractor;
import lombok.RequiredArgsConstructor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Classe responsavel por converter o token gerado pelo Keycloak
 * de maneira a atribuir os authorities do jeito que o spring security
 * utiliza.
 */
@Component
@RequiredArgsConstructor
public class KeycloakJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final JwtGrantedAuthoritiesConverter defaultGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    private AuthorityExtractor authorityExtractor = new AuthorityExtractor();

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = Stream
                .concat(defaultGrantedAuthoritiesConverter.convert(jwt).stream()
                        , extractAuthorities(jwt).stream())
                .collect(Collectors.toSet());
        return new JwtAuthenticationToken(jwt, authorities);
    }

    /**
     * orquestra a extração dos authorities
     * @param jwt
     * @return Collection<GrantedAuthority> contendo as roles e scopes do jwt
     */
    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        Set<String> rolesWithPrefix = new HashSet<>();
        rolesWithPrefix.addAll(authorityExtractor.realmAccess(jwt.getClaim("realm_access")));
        rolesWithPrefix.addAll(authorityExtractor.resourceAccess(jwt.getClaim("resource_access")));
        return AuthorityUtils.createAuthorityList(rolesWithPrefix.toArray(new String[0]));
    }
}
```

E então adicionar este Converter nas tuas configurações do security:

``` java
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class ResourceServerConfiguration extends WebSecurityConfigurerAdapter {

    private final KeycloakJwtAuthenticationConverter keycloakJwtAuthenticationConverter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests(authz -> authz
                        .antMatchers("/**")
                        .authenticated())
                .oauth2ResourceServer()
                .jwt()
                .jwtAuthenticationConverter(keycloakJwtAuthenticationConverter);

    }
}
```