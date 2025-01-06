package com.mysite.sbb.answer;

import lombok.Getter;

import java.time.LocalDateTime;

@Getter
public class AnswerDto {
    private Integer id;
    private String content;
    private LocalDateTime createDate;
    private LocalDateTime modifyDate;
    private String authorName;
    private Integer voterCount;

    public AnswerDto(Answer answer) {
        this.id = answer.getId();
        this.content = answer.getContent();
        this.createDate = answer.getCreateDate();
        this.modifyDate = answer.getModifyDate();
        this.authorName = answer.getAuthor().getUsername();
        this.voterCount = answer.voter.size();
    }
}
