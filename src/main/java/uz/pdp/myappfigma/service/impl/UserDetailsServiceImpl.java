package uz.pdp.myappfigma.service.impl;


import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import uz.pdp.myappfigma.dto.auth.CustomUserDetails;
import uz.pdp.myappfigma.entity.AuthUser;
import uz.pdp.myappfigma.repository.AuthUserRepository;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {


    private final AuthUserRepository authUserRepository;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AuthUser user = authUserRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("bad credentials"));
        return new CustomUserDetails(user);
    }
}

