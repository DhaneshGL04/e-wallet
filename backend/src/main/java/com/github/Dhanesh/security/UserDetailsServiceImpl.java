package com.github.Dhanesh.security;

import com.github.Dhanesh.model.User;
import com.github.Dhanesh.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.text.MessageFormat;

import static com.github.Dhanesh.common.Constants.NOT_FOUND_USERNAME;

/**
 * Service used for UserDetails related operations
 */
@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        final User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(MessageFormat.format(NOT_FOUND_USERNAME, username)));
        return UserDetailsImpl.build(user);
    }
}
