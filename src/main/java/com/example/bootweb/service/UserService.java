package com.example.bootweb.service;

import com.example.bootweb.dto.RegistrationRequestDto;
import com.example.bootweb.dto.RegistrationResponseDto;
import com.example.bootweb.entity.TokenEntity;
import com.example.bootweb.entity.UserEntity;
import com.example.bootweb.mapper.UserMapper;
import com.example.bootweb.repository.TokenRepository;
import com.example.bootweb.repository.UserRepository;
import com.example.bootweb.support.security.Roles;
import com.example.bootweb.support.security.TokenGenerator;
import com.example.bootweb.support.security.TokenNotFoundException;
import com.example.bootweb.support.security.XTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

@Service
@Transactional
@RequiredArgsConstructor
public class UserService implements UserDetailsService, XTokenService {
    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final UserMapper mapper;
    private final PasswordEncoder passwordEncoder;
    private final TokenGenerator tokenGenerator;

    private static final List<UserEntity> users = Collections.synchronizedList(new ArrayList<>());
    private static final List<TokenEntity> tokens = Collections.synchronizedList(new ArrayList<>());

    private static final List<UserEntity> usersList = new CopyOnWriteArrayList<>();
    private static final List<TokenEntity> tokensList = new CopyOnWriteArrayList<>();


    public RegistrationResponseDto register(RegistrationRequestDto requestDto) {
        final var userEntity = mapper.fromRegistrationRequestDto(requestDto, List.of(Roles.ROLE_USER));

        //JPA
        // TODO: check if username is available
//        userEntity.setPassword(passwordEncoder.encode(userEntity.getPassword()));
//        final var user = userRepository.save(userEntity);
//        final var token = tokenRepository.save(new TokenEntity(tokenGenerator.generate(), user));

        //Synchronized Collection
        userEntity.setPassword(passwordEncoder.encode(userEntity.getPassword()));
        users.add(userEntity);
        final var token = new TokenEntity(tokenGenerator.generate(), userEntity);
        tokens.add(token);

        //Concurrent Collection
//        userEntity.setPassword(passwordEncoder.encode(userEntity.getPassword()));
//        usersList.add(userEntity);
//        final var token = new TokenEntity(tokenGenerator.generate(), userEntity);
//        tokensList.add(token);

        return mapper.registrationFromEntity(userEntity, token);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username)
                .map(mapper::detailsFromEntity)
                .orElseThrow(() -> new UsernameNotFoundException(username));
    }

    @Override
    public UserDetails findByToken(String token) {
        return tokenRepository.findByValue(token)
                .map(TokenEntity::getUser)
                .map(mapper::detailsFromEntity)
                .orElseThrow(() -> new TokenNotFoundException("token not found"));
    }
}
