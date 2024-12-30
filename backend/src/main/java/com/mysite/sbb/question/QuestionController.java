package com.mysite.sbb.question;

import com.mysite.sbb.category.Category;
import com.mysite.sbb.answer.Answer;
import com.mysite.sbb.answer.AnswerForm;
import com.mysite.sbb.answer.AnswerService;
import com.mysite.sbb.category.CategoryService;
import com.mysite.sbb.comment.CommentForm;
import com.mysite.sbb.comment.CommentService;
import com.mysite.sbb.user.SiteUser;
import com.mysite.sbb.user.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.security.Principal;
import java.util.List;

@RequestMapping("/question")
@RequiredArgsConstructor
@Controller
public class QuestionController {
    private final QuestionService questionService;
    private final AnswerService answerService;
    private final UserService userService;
    private final CategoryService categoryService;

    @GetMapping("/list")
    public String list(
            Model model,
            @RequestParam(value = "page", defaultValue = "0") int page,
            @RequestParam(value = "kw", defaultValue = "") String kw,
            @RequestParam(value = "category_id", defaultValue = "1") Integer categoryId,
            Principal principal) {
        List<Category> categoryList = categoryService.getAllCategories();
        Category category = categoryService.getCategory(categoryId);
        Page<Question> paging = questionService.getQuestions(category, page, kw);

        model.addAttribute("paging", paging);
        model.addAttribute("kw", kw);
        model.addAttribute("category_id", categoryId);
        model.addAttribute("categoryList", categoryList);

        return "question_list";
    }

    @GetMapping("/detail/{id}")
    public String detail(
            Model model,
            AnswerForm answerForm,
            CommentForm commentForm,
            @PathVariable("id") Integer id,
            @RequestParam(value = "page", defaultValue = "0") int page,
            @RequestParam(value = "order", defaultValue = "createDate") String order,
            Principal principal,
            HttpServletRequest request
    ) {
        Question question = questionService.getQuestion(id);

        String referer = request.getHeader("Referer");
        if (referer.contains("list")) {
            questionService.viewQuestion(question);
        }

        Page<Answer> paging = answerService.getAnswers(question, page, order);

        model.addAttribute("question", question);
        model.addAttribute("answerList", paging);
        model.addAttribute("order", order);

        if (principal instanceof OAuth2AuthenticationToken) {
            OAuth2AuthenticationToken oAuth2User = (OAuth2AuthenticationToken) principal;
            model.addAttribute("username", oAuth2User.getName());
        }
        else if (principal instanceof UsernamePasswordAuthenticationToken) {
            UsernamePasswordAuthenticationToken authToken = (UsernamePasswordAuthenticationToken) principal;

            Object principalDetails = authToken.getPrincipal();
            if (principalDetails instanceof UserDetails) {
                UserDetails userDetails = (UserDetails) principalDetails;
                model.addAttribute("username", userDetails.getUsername());
            }
        }

        return "question_detail";
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/create")
    public String create(QuestionForm questionForm, @RequestParam ("category_id") Integer categoryId) {
        Category category = categoryService.getCategory(categoryId);
        questionForm.setCategory(category);

        return "question_form";
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/create")
    public String create(@Valid QuestionForm questionForm, BindingResult bindingResult, Principal principal) {
        if (bindingResult.hasErrors()) {
            return "question_form";
        }

        SiteUser siteUser = userService.getUser(principal.getName());
        questionService.create(questionForm.getCategory(), questionForm.getSubject(), questionForm.getContent(), siteUser);
        return "redirect:/question/list?category_id=%s".formatted(questionForm.getCategory().getId());
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/modify/{id}")
    public String modify(QuestionForm questionForm, @PathVariable("id") Integer id, Principal principal) {
        Question question = questionService.getQuestion(id);
        if(!question.getAuthor().getUsername().equals(principal.getName())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "수정권한이 없습니다.");
        }

        questionForm.setSubject(question.getSubject());
        questionForm.setContent(question.getContent());
        return "question_form";
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/modify/{id}")
    public String modify(@Valid QuestionForm questionForm, BindingResult bindingResult, Principal principal, @PathVariable("id") Integer id) {
        if (bindingResult.hasErrors()) {
            return "question_form";
        }

        Question question = questionService.getQuestion(id);
        if (!question.getAuthor().getUsername().equals(principal.getName())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "수정권한이 없습니다.");
        }

        questionService.modify(question, questionForm.getSubject(), questionForm.getContent());
        return String.format("redirect:/question/detail/%s", id);
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/delete/{id}")
    public String delete(Principal principal, @PathVariable("id") Integer id) {
        Question question = questionService.getQuestion(id);
        if(!question.getAuthor().getUsername().equals(principal.getName())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "삭제권한이 없습니다.");
        }

        questionService.delete(question);
        return "redirect:/";
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("vote/{id}")
    public String vote(Principal principal, @PathVariable("id") Integer id) {
        Question question = questionService.getQuestion(id);
        SiteUser siteUser = userService.getUser(principal.getName());
        questionService.vote(question, siteUser);

        return String.format("redirect:/question/detail/%s", id);
    }
}
