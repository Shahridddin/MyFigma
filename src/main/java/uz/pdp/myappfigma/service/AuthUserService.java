package uz.pdp.myappfigma.service;


import uz.pdp.myappfigma.dto.auth.GenerateTokenRequest;
import uz.pdp.myappfigma.dto.auth.RefreshTokenRequest;
import uz.pdp.myappfigma.dto.auth.TokenResponse;
import uz.pdp.myappfigma.dto.auth.UserSessionData;
import uz.pdp.myappfigma.dto.auth.AuthUserCreateDto;

public interface AuthUserService {

    TokenResponse generateAccessToken(GenerateTokenRequest dto);

    Long createUser( AuthUserCreateDto dto);

    TokenResponse refreshToken(RefreshTokenRequest dto);

    UserSessionData getMe();
}
