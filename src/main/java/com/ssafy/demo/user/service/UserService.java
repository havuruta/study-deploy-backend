package com.ssafy.demo.user.service;

import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.NoSuchElementException;

import com.ssafy.demo.exception.ErrorMessage;
import com.ssafy.demo.user.dto.UserDto;
import com.ssafy.demo.user.entity.Gender;
import com.ssafy.demo.user.entity.User;
import com.ssafy.demo.user.repository.UserRepository;

@RequiredArgsConstructor
@Service
public class UserService {

    private final UserRepository userRepository;
    private final EntityManager entityManager;
    // private final S3Service s3Service;

    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    public User findById(Long id) {
        return userRepository.findById(id).orElseThrow(
                () -> new NoSuchElementException(ErrorMessage.USER_NOT_FOUND));
    }


    public User findByEmail(String email) {
        return userRepository.findByEmail(email).orElseThrow(
                () -> new NoSuchElementException(ErrorMessage.USER_NOT_FOUND));
    }

    public User getReferenceByEmail(String email) {
        // 실제 엔터티를 로드하지 않고, 프록시 객체를 반환
        return entityManager.getReference(User.class, findByEmail(email).getId());
    }

    public void updateUserAdditionalInfo(String email, UserDto.Request userDto) {
        User user = findByEmail(email);
        user.setName(userDto.getNickname());
        user.setGender(Gender.fromString(userDto.getGender()));
        userRepository.save(user);
    }
    
    // @Transactional
    // public String generatePresignedUrl(String email) {
    //     URL presignedUrl = s3Service.getPresignedUrl(String.format("users/%s", email));
    //     return presignedUrl.toString();
    // }
    //
    // @Transactional
    // public void completeImageUpload(UserDto.ImageRequest imageRequest, String userEmail) {
    //     User user = findByEmail(userEmail);
    //     String userImageUrl = s3Service.getUserImageUrl(imageRequest.getPresignedUrl());
    //     user.setProfileImageUrl(userImageUrl);
    //
    //     userRepository.save(user);
    // }

}
