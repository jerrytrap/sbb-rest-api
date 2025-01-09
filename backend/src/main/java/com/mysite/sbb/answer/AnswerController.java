package com.mysite.sbb.answer;

import com.mysite.sbb.comment.CommentForm;
import com.mysite.sbb.comment.CommentService;
import com.mysite.sbb.global.ResponseDto;
import com.mysite.sbb.question.Question;
import com.mysite.sbb.question.QuestionService;
import com.mysite.sbb.user.SiteUser;
import com.mysite.sbb.user.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.security.Principal;
import java.util.List;
import java.util.stream.Collectors;

@RequestMapping("/api/v1/answers")
@RequiredArgsConstructor
@RestController
public class AnswerController {
    private final QuestionService questionService;
    private final AnswerService answerService;
    private final CommentService commentService;
    private final UserService userService;

    @GetMapping
    public ResponseDto<Page<AnswerDto>> getPageAnswers(
            @RequestParam("question_id") Integer questionId,
            @RequestParam(value = "page", defaultValue = "0") int page,
            @RequestParam(value = "sort", defaultValue = "createDate") String sort
    ) {
        Question question = questionService.getQuestion(questionId);
        Page<Answer> answers = answerService.getAnswers(question, page, sort);

        return new ResponseDto<>(convertPageToDto(answers));
    }

    @GetMapping("/{id}")
    public ResponseDto<AnswerDto> getAnswer(@PathVariable("id") Integer id) {
        Answer answer = answerService.getAnswer(id);
        return new ResponseDto<>(new AnswerDto(answer));
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping
    public ResponseDto<Void> createAnswer(
            @RequestBody @Valid AnswerForm answerForm,
            Principal principal,
            @RequestParam("question_id") Integer questionId
    ) {
        Question question = questionService.getQuestion(questionId);
        SiteUser siteUser = userService.getUser(principal.getName());
        answerService.create(question, answerForm.getContent(), siteUser);

        return new ResponseDto<>(HttpStatus.CREATED.value(), "질문 생성 완료");
    }

    @PreAuthorize("isAuthenticated()")
    @PatchMapping
    public ResponseDto<Void> modifyAnswer(
            @RequestBody @Valid AnswerForm answerForm,
            Principal principal,
            @RequestParam("id") Integer id
    ) {
        Answer answer = answerService.getAnswer(id);
        if (!answer.getAuthor().getUsername().equals(principal.getName())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "수정권한이 없습니다.");
        }
        answerService.modify(answer, answerForm.getContent());

        return new ResponseDto<>(HttpStatus.OK.value(), "답변 수정 완료");
    }

    @PreAuthorize("isAuthenticated()")
    @DeleteMapping("/{id}")
    public ResponseDto<String> deleteAnswer(Principal principal, @PathVariable("id") Integer id) {
        Answer answer = answerService.getAnswer(id);
        if (!answer.getAuthor().getUsername().equals(principal.getName())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "삭제권한이 없습니다.");
        }

        answerService.delete(answer);
        return new ResponseDto<>(HttpStatus.OK.value(), "답변 삭제 완료");
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/vote/{id}")
    public ResponseDto<Void> voteAnswer(Principal principal, @PathVariable("id") Integer id) {
        Answer answer = answerService.getAnswer(id);
        SiteUser siteUser = userService.getUser(principal.getName());
        answerService.vote(answer, siteUser);

        return new ResponseDto<>(HttpStatus.OK.value(), "추천 완료");
    }

    @GetMapping("/recent")
    public ResponseDto<List<AnswerDto>> getRecentAnswers() {
        List<Answer> answers = answerService.getRecentAnswers();

        return new ResponseDto<>(
                answers.stream()
                        .map(AnswerDto::new)
                        .collect(Collectors.toList())
        );
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/comment")
    public ResponseDto<Void> createAnswerComment(@RequestBody @Valid CommentForm commentForm, Principal principal) {
        Answer answer = answerService.getAnswer(commentForm.getAnswerId());
        SiteUser siteUser = userService.getUser(principal.getName());

        commentService.createComment(commentForm.getContent(), answer, siteUser);
        return new ResponseDto<>(HttpStatus.CREATED.value(), "댓글 생성 완료");
    }

    private Page<AnswerDto> convertPageToDto(Page<Answer> answerPage) {
        List<AnswerDto> answers = answerPage.getContent().stream()
                .map(AnswerDto::new)
                .collect(Collectors.toList());

        return new PageImpl<>(answers, answerPage.getPageable(), answerPage.getTotalElements());
    }
}
