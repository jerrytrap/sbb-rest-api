package com.mysite.sbb.question;

import com.mysite.sbb.category.Category;
import com.mysite.sbb.answer.AnswerService;
import com.mysite.sbb.category.CategoryService;
import com.mysite.sbb.user.SiteUser;
import com.mysite.sbb.user.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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
    private final AnswerService answerService;
    private final UserService userService;
    private final CategoryService categoryService;

    @GetMapping
    public Page<QuestionDto> getQuestions(
            @RequestParam(value = "page", defaultValue = "0") int page,
            @RequestParam(value = "kw", defaultValue = "") String kw,
            @RequestParam(value = "category_id", defaultValue = "1") Integer categoryId
    ) {
        Category category = categoryService.getCategory(categoryId);
        Page<Question> paging = questionService.getQuestions(category, page, kw);
        System.out.println(kw);
        return convertPageToDto(paging);
    }

    @GetMapping("/{id}")
    public QuestionDto getQuestion(@PathVariable Integer id) {
        Question question = questionService.getQuestion(id);

        return new QuestionDto(question);
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping
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
    @PatchMapping("/{id}")
    public ResponseEntity<String> modify(@Valid QuestionForm questionForm, Principal principal, @PathVariable("id") Integer id) {
        try {
            Question question = questionService.getQuestion(id);
            if (!question.getAuthor().getUsername().equals(principal.getName())) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "수정권한이 없습니다.");
            }

            questionService.modify(question, questionForm.getSubject(), questionForm.getContent());
            return new ResponseEntity<>("Success", HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @PreAuthorize("isAuthenticated()")
    @DeleteMapping("/{id}")
    public ResponseEntity<String> delete(Principal principal, @PathVariable("id") Integer id) {
        try {
            Question question = questionService.getQuestion(id);
            if(!question.getAuthor().getUsername().equals(principal.getName())) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "삭제권한이 없습니다.");
            }

            questionService.delete(question);
            return new ResponseEntity<>("Success", HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.NO_CONTENT);
        }
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/vote/{id}")
    public ResponseEntity<String> vote(Principal principal, @PathVariable("id") Integer id) {
        Question question = questionService.getQuestion(id);
        SiteUser siteUser = userService.getUser(principal.getName());
        questionService.vote(question, siteUser);

        return new ResponseEntity<>("Success", HttpStatus.OK);
    }

    private Page<QuestionDto> convertPageToDto(Page<Question> questionPage) {
        List<QuestionDto> questionDtos = questionPage.getContent().stream()
                .map(QuestionDto::new)
                .collect(Collectors.toList());

        return new PageImpl<>(questionDtos, questionPage.getPageable(), questionPage.getTotalElements());
    }
}
