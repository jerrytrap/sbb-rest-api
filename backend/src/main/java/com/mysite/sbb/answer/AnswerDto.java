package com.mysite.sbb.answer;

import com.mysite.sbb.comment.CommentDto;
import lombok.Getter;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Getter
public class AnswerDto {
    private Integer id;
    private String content;
    private LocalDateTime createDate;
    private LocalDateTime modifyDate;
    private String authorName;
    private Integer voterCount;
    private List<CommentDto> comments;

    public AnswerDto(Answer answer) {
        this.id = answer.getId();
        this.content = answer.getContent();
        this.createDate = answer.getCreateDate();
        this.modifyDate = answer.getModifyDate();
        this.authorName = answer.getAuthor().getUsername();
        this.voterCount = answer.voter.size();
        this.comments = answer.getCommentList()
                .stream()
                .map(CommentDto::new)
                .collect(Collectors.toList());
    }
}
