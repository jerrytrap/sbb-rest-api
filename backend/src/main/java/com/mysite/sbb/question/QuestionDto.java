package com.mysite.sbb.question;

import com.mysite.sbb.comment.CommentDto;
import lombok.Getter;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Getter
public class QuestionDto {
    private Integer id;
    private String category;
    private String subject;
    private String content;
    private String authorName;
    private LocalDateTime createDate;
    private LocalDateTime modifyDate;
    private Integer viewCount;
    private Integer voterCount;
    private Integer answerCount;
    private List<CommentDto> comments;

    public QuestionDto(Question question) {
        this.id = question.getId();
        this.category = question.getCategory().getName();
        this.subject = question.getSubject();
        this.content = question.getContent();
        this.authorName = question.getAuthor().getUsername();
        this.createDate = question.getCreateDate();
        this.modifyDate = question.getModifyDate();
        this.viewCount = question.getViewCount().intValue();
        this.voterCount = question.getVoter().size();
        this.answerCount = question.getAnswerList().size();
        this.comments = question.getCommentList()
                .stream()
                .map(CommentDto::new)
                .collect(Collectors.toList());
    }
}
