package com.mysite.sbb.user;

import com.mysite.sbb.util.DataNotFoundException;
import com.mysite.sbb.answer.Answer;
import com.mysite.sbb.answer.AnswerService;
import com.mysite.sbb.comment.Comment;
import com.mysite.sbb.comment.CommentService;
import com.mysite.sbb.question.Question;
import com.mysite.sbb.question.QuestionService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;
import java.util.InputMismatchException;
import java.util.List;

@RequiredArgsConstructor
@Controller
@RequestMapping("/user")
public class UserController {
    private final UserService userService;
    private final QuestionService questionService;
    private final AnswerService answerService;
    private final CommentService commentService;

    @GetMapping("/signup")
    public String signup(UserCreateForm userCreateForm) {
        return "signup_form";
    }

    @PostMapping("/signup")
    public String signup(@Valid UserCreateForm userCreateForm, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return "signup_form";
        }

        if (!userCreateForm.getPassword1().equals(userCreateForm.getPassword2())) {
            bindingResult.rejectValue("password2", "passwordInCorrect", "2개의 패스워드가 일치하지 않습니다.");
            return "signup_form";
        }

        try {
            userService.create(userCreateForm.getUsername(), userCreateForm.getEmail(), userCreateForm.getPassword1());
        } catch (DataIntegrityViolationException e) {
            bindingResult.reject("signupFailed", "이미 등록된 사용자입니다.");
            return "signup_form";
        } catch (Exception e) {
            bindingResult.reject("signupFailed", e.getMessage());
            return "signup_form";
        }

        return "redirect:/";
    }

    @GetMapping("/login")
    public String login() {
        return "login_form";
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
