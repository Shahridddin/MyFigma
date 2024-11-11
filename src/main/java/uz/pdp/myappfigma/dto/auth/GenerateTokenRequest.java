package uz.pdp.myappfigma.dto.auth;

import jakarta.validation.constraints.NotBlank;

public record GenerateTokenRequest(
        @NotBlank(message = "username can not be blank") String username,
        @NotBlank(message = "password can not be blank") String password) {

}
