package uz.pdp.myappfigma.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import uz.pdp.myappfigma.configuration.security.JwtTokenUtil;
import uz.pdp.myappfigma.configuration.security.UserSession;
import uz.pdp.myappfigma.dto.auth.AuthUserCreateDto;
import uz.pdp.myappfigma.dto.auth.GenerateTokenRequest;
import uz.pdp.myappfigma.dto.auth.RefreshTokenRequest;
import uz.pdp.myappfigma.dto.auth.TokenResponse;
import uz.pdp.myappfigma.repository.UserCreatRepository;
import uz.pdp.myappfigma.dto.auth.UserSessionData;
import uz.pdp.myappfigma.entity.AuthUser;
import uz.pdp.myappfigma.enums.JwtTokenType;

import java.util.Map;

@Service
public class UserCreateService implements AuthUserService {

    private final UserCreatRepository userCreatRepository;
    private final PasswordEncoder bcryptPasswordEncoder;
    private final UserSession userSession;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenUtil jwtTokenUtil;

    public UserCreateService(UserCreatRepository userCreatRepository, PasswordEncoder bcryptPasswordEncoder, UserSession userSession, AuthenticationManager authenticationManager, JwtTokenUtil jwtTokenUtil) {
        this.userCreatRepository = userCreatRepository;
        this.bcryptPasswordEncoder = bcryptPasswordEncoder;
        this.userSession = userSession;
        this.authenticationManager = authenticationManager;
        this.jwtTokenUtil = jwtTokenUtil;
    }


    @Override
    public TokenResponse generateAccessToken(GenerateTokenRequest dto) {
        String username = dto.username();
        String password = dto.password();
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(username, password);
        authenticationManager.authenticate(authentication);
        var accessTokenClaims = Map.<String, Object>of("token", JwtTokenType.ACCESS);
        var refreshTokenClaims = Map.<String, Object>of("token", JwtTokenType.REFRESH);
        String accessToken = jwtTokenUtil.generateAccessToken(username, accessTokenClaims);
        String refreshToken = jwtTokenUtil.generateRefreshToken(username, refreshTokenClaims);
        return new TokenResponse(accessToken, refreshToken);    }

    @Override
    public Long createUser(AuthUserCreateDto dto) {
        AuthUser authUser = new AuthUser();
        authUser.setEmail(dto.email());
        authUser.setUsername(dto.username());
        authUser.setPassword(bcryptPasswordEncoder.encode(dto.password()));
        authUser.setFirsName(dto.firstName());
        authUser.setLastName(dto.lastName());
        userCreatRepository.save(authUser);
        return authUser.getId();
    }


//    public String generateRefreshToken(String username, Map<String, Object> claims) {
//        return Jwts.builder()
//                .setSubject(username)
//                .setIssuedAt(new Date(System.currentTimeMillis()))
//                .setIssuer(jwtProperties.getIssuer())
//                .setExpiration(jwtProperties.getRefreshTokenTtl())
//                .signWith(signingKey, SignatureAlgorithm.HS256)
//                .addClaims(claims)
//                .compact();
//    }

    @Override
    public TokenResponse refreshToken(RefreshTokenRequest dto) {
        return null;
    }

    @Override
    public UserSessionData getMe() {
        return userSession.requireUserData();
    }
}

