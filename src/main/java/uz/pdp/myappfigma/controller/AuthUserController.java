package uz.pdp.myappfigma.controller;


import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import uz.pdp.myappfigma.dto.BaseResponse;
import uz.pdp.myappfigma.dto.auth.GenerateTokenRequest;
import uz.pdp.myappfigma.dto.auth.RefreshTokenRequest;
import uz.pdp.myappfigma.dto.auth.TokenResponse;
import uz.pdp.myappfigma.dto.auth.UserSessionData;
import uz.pdp.myappfigma.dto.auth.AuthUserCreateDto;
import uz.pdp.myappfigma.service.AuthUserService;

@RestController
@RequestMapping("/auth")
public class AuthUserController {
    private final AuthUserService authUserService;

    public AuthUserController(AuthUserService authUserService) {
        this.authUserService = authUserService;
    }

    @PostMapping("/token")
    public BaseResponse<TokenResponse> generateToken(@Valid @RequestBody GenerateTokenRequest requestBody) {
        TokenResponse response = authUserService.generateAccessToken(requestBody);
        return new BaseResponse<>(response);
    }

    @PostMapping("/refresh")
    public BaseResponse<TokenResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest requestBody) {
        TokenResponse response = authUserService.refreshToken(requestBody);
        return new BaseResponse<>(response);
    }

    @PostMapping("/create")
    @ResponseStatus(HttpStatus.CREATED)
    public BaseResponse<Long> create(@Valid @RequestBody AuthUserCreateDto dto) {
        Long id = authUserService.createUser(dto);
        return new BaseResponse<>(id);
    }

    @GetMapping("/me")
    @ResponseStatus(HttpStatus.CREATED)
    public BaseResponse<UserSessionData> getMe() {
        var userSessionData = authUserService.getMe();
        return new BaseResponse<>(userSessionData);
    }

}