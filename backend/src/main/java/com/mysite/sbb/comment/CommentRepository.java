package com.mysite.sbb.comment;

import com.mysite.sbb.user.SiteUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface CommentRepository extends JpaRepository<Comment, Integer> {
    List<Comment> findAllByAuthor(SiteUser user);

    @Query("SELECT c FROM Comment c "
            + "ORDER BY c.createDate desc "
            + "LIMIT :limit")
    List<Comment> findAllOrderByCreateDateLimit(Integer limit);
}
