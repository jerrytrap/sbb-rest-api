package com.mysite.sbb.comment;

import com.mysite.sbb.answer.Answer;
import com.mysite.sbb.answer.AnswerService;
import com.mysite.sbb.question.Question;
import com.mysite.sbb.question.QuestionService;
import com.mysite.sbb.user.SiteUser;
import com.mysite.sbb.user.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.security.Principal;
import java.util.List;
import java.util.stream.Collectors;

@RequestMapping("/api/v1/comment")
@RequiredArgsConstructor
@RestController
public class CommentController {
    private final CommentService commentService;
    private final AnswerService answerService;
    private final QuestionService questionService;
    private final UserService userService;

    @GetMapping("/question")
    public List<CommentDto> getQuestionComment(@RequestParam("question_id") Integer questionId) {
        Question question = questionService.getQuestion(questionId);
        return commentService.getCommentsByQuestion(question)
                .stream()
                .map(CommentDto::new)
                .collect(Collectors.toList());
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping
    public ResponseEntity<String> createQuestionComment(
            @RequestBody @Valid CommentForm commentForm,
            Principal principal
    ) {
        try {
            Question question = questionService.getQuestion(commentForm.getQuestionId());
            SiteUser siteUser = userService.getUser(principal.getName());

            commentService.createComment(commentForm.getContent(), question, siteUser);
            return new ResponseEntity<>("Success", HttpStatus.CREATED);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/create/answer/{id}")
    public String createAnswerComment(
            @ModelAttribute CommentForm commentForm,
            @PathVariable Integer id,
            Principal principal
    ) {
        Answer answer = answerService.getAnswer(commentForm.getAnswerId());
        SiteUser siteUser = userService.getUser(principal.getName());

        commentService.createComment(commentForm.getContent(), answer, siteUser);
        return "redirect:/question/detail/%s".formatted(id);
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/modify/{id}")
    public String modify(@Valid CommentForm commentForm, BindingResult bindingResult, @PathVariable("id") Integer id, Principal principal) {
        if (bindingResult.hasErrors()) {
            return "comment_form";
        }

        Comment comment = commentService.getComment(id);
        if (!comment.getAuthor().getUsername().equals(principal.getName())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "수정권한이 없습니다.");
        }

        commentService.modify(comment, commentForm.getContent());
        return String.format("redirect:/question/detail/%s", comment.getQuestion().getId());
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/modify/{id}")
    public String modify(CommentForm commentForm, @PathVariable("id") Integer id, Principal principal) {
        Comment comment = commentService.getComment(id);

        if (!comment.getAuthor().getUsername().equals(principal.getName())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "수정권한이 없습니다.");
        }

        commentForm.setContent(comment.getContent());
        return "comment_form";
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/delete/{id}")
    public String delete(@PathVariable Integer id, Principal principal, HttpServletRequest request) {
        Comment comment = commentService.getComment(id);

        if (!comment.getAuthor().getUsername().equals(principal.getName())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "삭제권한이 없습니다.");
        }
        commentService.delete(comment);

        String referer = request.getHeader("Referer");
        if (referer != null && !referer.isEmpty()) {
            return "redirect:" + referer;
        }

        return "redirect:/";
    }

    @GetMapping("/recent")
    public String recent(Model model) {
        List<Comment> comments = commentService.getRecentComments();
        model.addAttribute("comment_list", comments);

        return "comment_recent";
    }
}
