package com.mysite.sbb.question;

import com.mysite.sbb.category.Category;
import com.mysite.sbb.answer.Answer;
import com.mysite.sbb.answer.AnswerForm;
import com.mysite.sbb.answer.AnswerService;
import com.mysite.sbb.category.CategoryService;
import com.mysite.sbb.comment.CommentForm;
import com.mysite.sbb.user.SiteUser;
import com.mysite.sbb.user.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
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
    private final AnswerService answerService;
    private final UserService userService;
    private final CategoryService categoryService;

    @GetMapping
    @ResponseBody
    public List<QuestionDto> getQuestions(
            @RequestParam(value = "page", defaultValue = "0") int page,
            @RequestParam(value = "kw", defaultValue = "") String kw,
            @RequestParam(value = "category_id", defaultValue = "1") Integer categoryId
    ) {
        Category category = categoryService.getCategory(categoryId);
        Page<Question> paging = questionService.getQuestions(category, page, kw);

        return paging.stream()
                .map(QuestionDto::new)
                .collect(Collectors.toList());
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
    @PostMapping("/create")
    public ResponseEntity<String> create(@Valid QuestionForm questionForm, Principal principal) {
        try {
            SiteUser siteUser = userService.getUser(principal.getName());
            questionService.create(new Category(1, "자유"), questionForm.getSubject(), questionForm.getContent(), siteUser);
            return new ResponseEntity<>("Success", HttpStatus.CREATED);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
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
