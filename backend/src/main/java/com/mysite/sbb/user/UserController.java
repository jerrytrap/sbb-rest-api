package com.mysite.sbb.user;

import com.mysite.sbb.global.ResponseDto;
import com.mysite.sbb.security.JwtTokenProvider;
import com.mysite.sbb.util.DataNotFoundException;
import com.mysite.sbb.answer.Answer;
import com.mysite.sbb.answer.AnswerService;
import com.mysite.sbb.comment.Comment;
import com.mysite.sbb.comment.CommentService;
import com.mysite.sbb.question.Question;
import com.mysite.sbb.question.QuestionService;
import com.mysite.sbb.util.LoginFailException;
import com.mysite.sbb.util.UserConflictException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.InputMismatchException;
import java.util.List;

@RequiredArgsConstructor
@RestController
@RequestMapping("/user")
public class UserController {
    private final UserService userService;
    private final QuestionService questionService;
    private final AnswerService answerService;
    private final CommentService commentService;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;

    @PostMapping("/signup")
    public ResponseDto<Void> signup(@RequestBody @Valid UserCreateForm userCreateForm) {
        if (!userCreateForm.getPassword1().equals(userCreateForm.getPassword2())) {
            return new ResponseDto<>(400, "2개의 패스워드가 일치하지 않습니다.");
        }

        try {
            userService.create(userCreateForm.getUsername(), userCreateForm.getEmail(), userCreateForm.getPassword1());
        } catch (DataIntegrityViolationException e) {
            throw new UserConflictException("아이디나 이메일이 이미 존재합니다.");
        }

        return new ResponseDto<>(HttpStatus.CREATED.value(), "회원가입 성공");
    }

    @PostMapping("/login")
    public ResponseDto<?> login(@RequestBody @Valid LoginRequestBody loginRequestBody) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequestBody.getUsername(), loginRequestBody.getPassword())
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);

            SiteUser siteUser = userService.getUser(authentication.getName());
            String token = jwtTokenProvider.createToken(authentication.getName());

            return new ResponseDto<>(
                    200,
                    "로그인 성공",
                    new UserResponseDto(
                            siteUser.getUsername(),
                            siteUser.getEmail(),
                            token
                    )
            );
        } catch (AuthenticationException e) {
            throw new LoginFailException("아이디, 비밀번호를 다시 확인해주세요.");
        }
    }

    @GetMapping("/info")
    public String info(Model model, Principal principal) {
        SiteUser siteUser = userService.getUser(principal.getName());
        List<Question> questionList = questionService.getQuestions(siteUser);
        List<Answer> answerList = answerService.getAnswers(siteUser);
        List<Comment> commentList = commentService.getComments(siteUser);

        model.addAttribute("user", siteUser);
        model.addAttribute("question_list", questionList);
        model.addAttribute("answer_list", answerList);
        model.addAttribute("comment_list", commentList);

        return "user_info";
    }

    @GetMapping("/login/temp_password")
    public String tempPassword() {
        return "email_check_form";
    }

    @PostMapping("/login/temp_password")
    public String tempPassword(Model model, String email) {
        try {
            SiteUser user = userService.getUserByEmail(email);
            userService.sendTemporaryPassword(user);
        } catch (DataNotFoundException e) {
            model.addAttribute("error", "등록되지 않은 사용자입니다.");
            return "email_check_form";
        }

        return "redirect:/user/login";
    }

    @GetMapping("/password_change")
    public String passwordChange() {
        return "password_change_form";
    }

    @PostMapping("/password_change")
    public String passwordChange(
            Model model,
            @RequestParam("old_password") String oldPassword,
            @RequestParam("new_password") String newPassword,
            Principal principal) {
        try {
            SiteUser user = userService.getUser(principal.getName());
            userService.changePassword(user, oldPassword, newPassword);
        } catch (InputMismatchException e) {
            model.addAttribute("error", "현재 비밀번호를 다시 입력해주세요.");
            return "password_change_form";
        }

        return "redirect:/";
    }
}
