package com.mysite.sbb.question;

import com.mysite.sbb.util.DataNotFoundException;
import com.mysite.sbb.category.Category;
import com.mysite.sbb.user.SiteUser;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@RequiredArgsConstructor
@Service
public class QuestionService {
    private final QuestionRepository questionRepository;
    private static final int QUESTION_PAGE_DATA_COUNT = 10;

    public void viewQuestion(Question question) {
        question.setViewCount(question.getViewCount() + 1);
        questionRepository.save(question);
    }

    public Question getQuestion(Integer id) {
        Optional<Question> q = questionRepository.findById(id);

        if (q.isPresent()) {
            Question question = q.get();

            return question;
        } else {
            throw new DataNotFoundException("question not found");
        }
    }

    public List<Question> getQuestions(SiteUser user) {
        return questionRepository.findAllByAuthor(user);
    }

    public Page<Question> getQuestions(Category category, int page, String kw) {
        List<Sort.Order> sorts = new ArrayList<>();
        sorts.add(Sort.Order.desc("createDate"));
        Pageable pageable = PageRequest.of(page, QUESTION_PAGE_DATA_COUNT, Sort.by(sorts));

        return questionRepository.findAllByCategoryAndKeyword(category, kw, pageable);
    }

    public void create(Category category, String subject, String content, SiteUser user) {
        Question question = Question.builder()
                .category(category)
                .subject(subject)
                .content(content)
                .author(user)
                .viewCount(0L)
                .build();

        questionRepository.save(question);
    }

    public void modify(Question question, String subject, String content) {
        question.setSubject(subject);
        question.setContent(content);
        questionRepository.save(question);
    }

    public void delete(Question question) {
        questionRepository.delete(question);
    }

    public void vote(Question question, SiteUser siteUser) {
        question.getVoter().add(siteUser);
        questionRepository.save(question);
    }
}
