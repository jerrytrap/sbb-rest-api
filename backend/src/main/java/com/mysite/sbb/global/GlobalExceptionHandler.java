package com.mysite.sbb.global;

import com.mysite.sbb.util.LoginFailException;
import com.mysite.sbb.util.UserConflictException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(UserConflictException.class)
    public ResponseEntity<ErrorResponseDto> handleUserConflictException(UserConflictException e) {
        ErrorResponseDto errorResponseDto = new ErrorResponseDto(HttpStatus.CONFLICT.value(), e.getMessage());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(errorResponseDto);
    }

    @ExceptionHandler(LoginFailException.class)
    public ResponseEntity<ErrorResponseDto> handleLoginFailException(LoginFailException e) {
        ErrorResponseDto errorResponseDto = new ErrorResponseDto(HttpStatus.BAD_REQUEST.value(), e.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponseDto);
    }
}
