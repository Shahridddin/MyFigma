package uz.pdp.myappfigma.properties;


import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PositiveOrZero;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.Date;

@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
    /**
     * this field is
     */
    @NotBlank
    private String secretKey;
    @NotNull
    @PositiveOrZero
    private Long accessTokenTtl;
    @NotNull
    @PositiveOrZero
    private Long refreshTokenTtl;
    @NotBlank
    private String issuer;

    public Date getAccessTokenTtl() {
        return new Date(System.currentTimeMillis() + accessTokenTtl * 1000);
    }

    public Date getRefreshTokenTtl() {
        return new Date(System.currentTimeMillis() + refreshTokenTtl * 1000);
    }
}