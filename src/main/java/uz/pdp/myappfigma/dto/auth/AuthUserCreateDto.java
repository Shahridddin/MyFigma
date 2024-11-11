package uz.pdp.myappfigma.dto.auth;

import uz.pdp.myappfigma.enums.AuthRole;

public record AuthUserCreateDto(
        String firstName,
        String lastName,
        String email,
        String username,
        String password,
        AuthRole authRole,
        boolean isActive) {
}