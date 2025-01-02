package com.mysite.sbb.global;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class ErrorResponseDto extends RuntimeException {
    private int code;
    private String message;
}
