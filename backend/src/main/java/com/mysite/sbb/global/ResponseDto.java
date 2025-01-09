package com.mysite.sbb.global;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ResponseDto<T> {
    private Integer code;
    private String message;
    private T data;

    public ResponseDto(Integer code, String message) {
        this(code, message, null);
    }

    public ResponseDto(T data) {
        this(null, null, data);
    }
}
