package com.mysite.sbb.answer;

import com.mysite.sbb.util.DataNotFoundException;
import com.mysite.sbb.question.Question;
import com.mysite.sbb.user.SiteUser;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@RequiredArgsConstructor
@Service
public class AnswerService {
    private final AnswerRepository answerRepository;
    private static final int ANSWER_PAGE_DATA_COUNT = 5;
    private static final int RECENT_PAGE_COUNT = 10;

    public Answer create(Question question, String content, SiteUser author) {
        Answer answer = Answer.builder()
                .content(content)
                .question(question)
                .author(author)
                .build();

        answerRepository.save(answer);
        return answer;
    }

    public Answer getAnswer(Integer id) {
        Optional<Answer> answer = answerRepository.findById(id);
        if (answer.isPresent()) {
            return answer.get();
        } else {
            throw new DataNotFoundException("answer not found");
        }
    }

    public List<Answer> getAnswers(SiteUser user) {
        return answerRepository.findAllByAuthor(user);
    }

    public Page<Answer> getAnswers(Question question, Integer page, String columName) {
        Pageable pageable = PageRequest.of(page, ANSWER_PAGE_DATA_COUNT);

        if (columName.equals("createDate")) {
            return answerRepository.findAllByQuestionOrderByCreateDateDesc(question, pageable);
        } else if (columName.equals("voter")) {
            return answerRepository.findAllWithVoterCountDesc(question, pageable);
        }
        throw new IllegalArgumentException("wrong column name");
    }

    public List<Answer> getRecentAnswers() {
        return answerRepository.findAllOrderByCreateDateLimit(RECENT_PAGE_COUNT);
    }

    public void modify(Answer answer, String content) {
        answer.setContent(content);
        answerRepository.save(answer);
    }

    public void delete(Answer answer) {
        answerRepository.delete(answer);
    }

    public void vote(Answer answer, SiteUser siteUser) {
        answer.getVoter().add(siteUser);
        answerRepository.save(answer);
    }
}
