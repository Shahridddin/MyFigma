package uz.pdp.myappfigma.dto.auth;

import jakarta.validation.constraints.NotBlank;

public record RefreshTokenRequest(@NotBlank(message = "token can not be blank") String token) {
}
