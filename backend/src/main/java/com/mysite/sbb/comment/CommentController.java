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

    @GetMapping("/{id}")
    public ResponseEntity<String> getComment(@PathVariable Integer id) {
        Comment comment = commentService.getComment(id);
        return new ResponseEntity<>(comment.getContent(), HttpStatus.OK);
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/question")
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
    @PostMapping("/answer")
    public ResponseEntity<String> createAnswerComment(
            @RequestBody @Valid CommentForm commentForm,
            Principal principal
    ) {
        try {
            Answer answer = answerService.getAnswer(commentForm.getAnswerId());
            SiteUser siteUser = userService.getUser(principal.getName());

            commentService.createComment(commentForm.getContent(), answer, siteUser);
            return new ResponseEntity<>("Success", HttpStatus.CREATED);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @PreAuthorize("isAuthenticated()")
    @PatchMapping("/{id}")
    public ResponseEntity<String> modify(@RequestBody @Valid CommentForm commentForm, @PathVariable("id") Integer id, Principal principal) {
        try {
            Comment comment = commentService.getComment(id);
            if (!comment.getAuthor().getUsername().equals(principal.getName())) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "수정권한이 없습니다.");
            }

            commentService.modify(comment, commentForm.getContent());
            return new ResponseEntity<>("Success", HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
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
