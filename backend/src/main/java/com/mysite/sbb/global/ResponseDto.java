package com.mysite.sbb.global;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Getter;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Getter
@AllArgsConstructor
public class ResponseDto<T> {
    private int code;
    private String message;
    private T data;

    public ResponseDto(int code, String message) {
        this(code, message, null);
    }
}
