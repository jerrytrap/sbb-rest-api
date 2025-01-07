package com.mysite.sbb.comment;

import com.mysite.sbb.util.DataNotFoundException;
import com.mysite.sbb.answer.Answer;
import com.mysite.sbb.question.Question;
import com.mysite.sbb.user.SiteUser;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@RequiredArgsConstructor
@Service
public class CommentService {
    private final CommentRepository commentRepository;
    private static final int RECENT_PAGE_COUNT = 5;

    public void createComment(String content, Question question, SiteUser user) {
        Comment comment = Comment.builder()
                .content(content)
                .question(question)
                .author(user)
                .build();

        commentRepository.save(comment);
    }

    public void createComment(String content, Answer answer, SiteUser user) {
        Comment comment = Comment.builder()
                .content(content)
                .answer(answer)
                .author(user)
                .build();

        commentRepository.save(comment);
    }

    public Comment getComment(Integer id) {
        Optional<Comment> c = commentRepository.findById(id);
        if (c.isPresent()) {
            return c.get();
        } else {
            throw new DataNotFoundException("comment not found");
        }
    }

    public List<Comment> getComments(SiteUser user) {
        return commentRepository.findAllByAuthor(user);
    }

    public List<Comment> getRecentComments() {
        return commentRepository.findAllOrderByCreateDateLimit(RECENT_PAGE_COUNT);
    }

    public void modify(Comment comment, String content) {
        comment.setContent(content);
        commentRepository.save(comment);
    }

    public void delete(Comment comment) {
        commentRepository.delete(comment);
    }
}
