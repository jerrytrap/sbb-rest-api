package com.mysite.sbb.question;

import com.mysite.sbb.category.Category;
import com.mysite.sbb.category.CategoryService;
import com.mysite.sbb.comment.CommentForm;
import com.mysite.sbb.comment.CommentService;
import com.mysite.sbb.global.ResponseDto;
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

@RequestMapping("/api/v1/questions")
@RequiredArgsConstructor
@RestController
public class QuestionController {
    private final QuestionService questionService;
    private final UserService userService;
    private final CategoryService categoryService;
    private final CommentService commentService;

    @GetMapping
    public ResponseDto<Page<QuestionDto>> getPageQuestions(
            @RequestParam(value = "page", defaultValue = "0") int page,
            @RequestParam(value = "kw", defaultValue = "") String kw,
            @RequestParam(value = "category_id", defaultValue = "1") Integer categoryId
    ) {
        Category category = categoryService.getCategory(categoryId);
        Page<Question> paging = questionService.getQuestions(category, page, kw);

        return new ResponseDto<>(convertPageToDto(paging));
    }

    @GetMapping("/{id}")
    public ResponseDto<QuestionDto> getQuestion(@PathVariable Integer id) {
        Question question = questionService.getQuestion(id);
        questionService.viewQuestion(question);

        return new ResponseDto<>(new QuestionDto(question));
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping
    public ResponseDto<Void> createQuestion(@RequestBody @Valid QuestionForm questionForm, Principal principal) {
        SiteUser siteUser = userService.getUser(principal.getName());
        Category category = categoryService.getCategory(questionForm.getCategoryId());
        questionService.create(category, questionForm.getSubject(), questionForm.getContent(), siteUser);

        return new ResponseDto<>(HttpStatus.CREATED.value(), "질문 생성 완료");
    }

    @PreAuthorize("isAuthenticated()")
    @PatchMapping("/{id}")
    public ResponseDto<Void> modifyQuestion(
            @RequestBody @Valid QuestionForm questionForm,
            Principal principal,
            @PathVariable("id") Integer id
    ) {
        Question question = questionService.getQuestion(id);
        if (!question.getAuthor().getUsername().equals(principal.getName())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "수정 권한이 없습니다.");
        }
        questionService.modify(question, questionForm.getSubject(), questionForm.getContent());

        return new ResponseDto<>(HttpStatus.OK.value(), "질문 수정 완료");
    }

    @PreAuthorize("isAuthenticated()")
    @DeleteMapping("/{id}")
    public ResponseDto<Void> deleteQuestion(Principal principal, @PathVariable("id") Integer id) {
        Question question = questionService.getQuestion(id);
        if(!question.getAuthor().getUsername().equals(principal.getName())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "삭제 권한이 없습니다.");
        }

        questionService.delete(question);
        return new ResponseDto<>(HttpStatus.OK.value(), "질문 삭제 완료");
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/vote/{id}")
    public ResponseDto<Void> voteQuestion(Principal principal, @PathVariable("id") Integer id) {
        Question question = questionService.getQuestion(id);
        SiteUser siteUser = userService.getUser(principal.getName());
        questionService.vote(question, siteUser);

        return new ResponseDto<>(HttpStatus.OK.value(), "추천 완료");
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/comment")
    public ResponseDto<Void> createQuestionComment(@RequestBody @Valid CommentForm commentForm, Principal principal) {
        Question question = questionService.getQuestion(commentForm.getQuestionId());
        SiteUser siteUser = userService.getUser(principal.getName());

        commentService.createComment(commentForm.getContent(), question, siteUser);
        return new ResponseDto<>(HttpStatus.CREATED.value(), "댓글 생성 완료");
    }

    private Page<QuestionDto> convertPageToDto(Page<Question> questionPage) {
        List<QuestionDto> questions = questionPage.getContent()
                .stream()
                .map(QuestionDto::new)
                .collect(Collectors.toList());

        return new PageImpl<>(questions, questionPage.getPageable(), questionPage.getTotalElements());
    }
}
