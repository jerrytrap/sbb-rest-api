package com.mysite.sbb.user;

import com.mysite.sbb.answer.AnswerDto;
import com.mysite.sbb.comment.CommentDto;
import com.mysite.sbb.global.ResponseDto;
import com.mysite.sbb.question.QuestionDto;
import com.mysite.sbb.util.DataNotFoundException;
import com.mysite.sbb.answer.Answer;
import com.mysite.sbb.answer.AnswerService;
import com.mysite.sbb.comment.Comment;
import com.mysite.sbb.comment.CommentService;
import com.mysite.sbb.question.Question;
import com.mysite.sbb.question.QuestionService;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.security.Principal;
import java.util.InputMismatchException;
import java.util.List;
import java.util.stream.Collectors;

@CrossOrigin
@RequiredArgsConstructor
@RestController
@RequestMapping("/user")
public class UserController {
    private final UserService userService;
    private final QuestionService questionService;
    private final AnswerService answerService;
    private final CommentService commentService;

    @PreAuthorize("isAuthenticated()")
    @PostMapping
    public ResponseDto<UserResponseDto> getUser(Principal principal) {
        SiteUser siteUser = userService.getUser(principal.getName());

        return new ResponseDto<>(
                200,
                "success",
                new UserResponseDto(
                        siteUser.getUsername(),
                        siteUser.getEmail()
                )
        );
    }

    @PostMapping("/signup")
    public ResponseDto<Void> signup(@RequestBody @Valid UserCreateForm userCreateForm) {
        if (!userCreateForm.getPassword1().equals(userCreateForm.getPassword2())) {
            return new ResponseDto<>(HttpStatus.BAD_REQUEST.value(), "2개의 패스워드가 일치하지 않습니다.");
        }
        userService.create(userCreateForm.getUsername(), userCreateForm.getEmail(), userCreateForm.getPassword1());
        return new ResponseDto<>(HttpStatus.CREATED.value(), "회원가입 성공");
    }

    @GetMapping("/status")
    public ResponseDto<String> checkLogin(HttpSession session) {
        SecurityContext securityContext = (SecurityContext) session.getAttribute("SPRING_SECURITY_CONTEXT");

        if (securityContext != null) {
            Authentication authentication = securityContext.getAuthentication();

            if (authentication != null && authentication.isAuthenticated()) {
                return new ResponseDto<>(HttpStatus.OK.value(), "username", authentication.getName());
            }
        }
        return new ResponseDto<>(HttpStatus.UNAUTHORIZED.value(), "not login");
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/questions")
    public ResponseDto<List<QuestionDto>> getQuestionsByUser(@RequestBody UserRequestDto user, Principal principal) {
        if (!user.getUsername().equals(principal.getName())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "조회 권한이 없습니다.");
        }

        SiteUser siteUser = userService.getUser(principal.getName());
        List<Question> questionList = questionService.getQuestions(siteUser);

        return new ResponseDto<>(
                questionList
                        .stream()
                        .map(QuestionDto::new)
                        .collect(Collectors.toList())
        );
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/answers")
    public ResponseDto<List<AnswerDto>> getAnswersByUser(@RequestBody UserRequestDto user, Principal principal) {
        if (!user.getUsername().equals(principal.getName())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "조회 권한이 없습니다.");
        }

        SiteUser siteUser = userService.getUser(principal.getName());
        List<Answer> answerList = answerService.getAnswers(siteUser);

        return new ResponseDto<>(
                answerList
                        .stream()
                        .map(AnswerDto::new)
                        .collect(Collectors.toList())
        );
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/comments")
    public ResponseDto<List<CommentDto>> getCommentsByUser(@RequestBody UserRequestDto user, Principal principal) {
        if (!user.getUsername().equals(principal.getName())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "조회 권한이 없습니다.");
        }

        SiteUser siteUser = userService.getUser(principal.getName());
        List<Comment> commentList = commentService.getComments(siteUser);

        return new ResponseDto<>(
                commentList
                        .stream()
                        .map(CommentDto::new)
                        .collect(Collectors.toList())
        );
    }

    @PostMapping("/email")
    public ResponseDto<Void> getTempPassword(@RequestBody EmailRequestDto emailDto) {
        try {
            SiteUser user = userService.getUserByEmail(emailDto.getEmail());
            userService.sendTemporaryPassword(user);
            return new ResponseDto<>(HttpStatus.OK.value(), "이메일 전송");
        } catch (DataNotFoundException e) {
            return new ResponseDto<>(HttpStatus.NOT_FOUND.value(), "가입된 이메일이 없습니다.");
        }
    }

    @PostMapping("/password_change")
    public ResponseDto<Void> passwordChange(
            @RequestBody PasswordRequestDto passwordRequestDto,
            Principal principal) {
        try {
            SiteUser user = userService.getUser(principal.getName());
            userService.changePassword(user, passwordRequestDto.getCurrentPassword(), passwordRequestDto.getNewPassword());
            return new ResponseDto<>(HttpStatus.OK.value(), "패스워드를 변경했습니다.");
        } catch (InputMismatchException e) {
            return new ResponseDto<>(HttpStatus.BAD_REQUEST.value(), "패스워드 불일치");
        }
    }
}
