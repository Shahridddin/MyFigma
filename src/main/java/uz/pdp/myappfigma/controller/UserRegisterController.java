package uz.pdp.myappfigma.controller;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import uz.pdp.myappfigma.dto.BaseResponse;
import uz.pdp.myappfigma.dto.auth.AuthUserCreateDto;
import uz.pdp.myappfigma.dto.auth.UserSessionData;
import uz.pdp.myappfigma.service.UserCreateService;

@RestController
@RequestMapping("/auth/register")
public class UserRegisterController {


    private final UserCreateService userCreateService;

    public UserRegisterController(UserCreateService userCreateService) {
        this.userCreateService = userCreateService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public BaseResponse<Long> create(@Valid @RequestBody AuthUserCreateDto dto){

        Long id = userCreateService.createUser(dto);
        return new BaseResponse<>(id);
    }


    @GetMapping("/me")
    public BaseResponse<UserSessionData> getMe(){
        UserSessionData userSessionData = userCreateService.getMe();
        return new BaseResponse<>(userSessionData);
    }
}
