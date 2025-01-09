package com.mysite.sbb.comment;

import com.mysite.sbb.global.ResponseDto;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.security.Principal;
import java.util.List;
import java.util.stream.Collectors;

@RequestMapping("/api/v1/comments")
@RequiredArgsConstructor
@RestController
public class CommentController {
    private final CommentService commentService;

    @GetMapping("/{id}")
    public ResponseDto<CommentDto> getComment(@PathVariable Integer id) {
        Comment comment = commentService.getComment(id);
        return new ResponseDto<>(new CommentDto(comment));
    }

    @PreAuthorize("isAuthenticated()")
    @PatchMapping("/{id}")
    public ResponseDto<Void> modifyComment(@RequestBody @Valid CommentForm commentForm, @PathVariable("id") Integer id, Principal principal) {
        Comment comment = commentService.getComment(id);
        if (!comment.getAuthor().getUsername().equals(principal.getName())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "수정권한이 없습니다.");
        }
        commentService.modify(comment, commentForm.getContent());

        return new ResponseDto<>(HttpStatus.OK.value(), "댓글 수정 완료");
    }

    @PreAuthorize("isAuthenticated()")
    @DeleteMapping("/{id}")
    public ResponseDto<Void> deleteComment(@PathVariable Integer id, Principal principal) {
        Comment comment = commentService.getComment(id);

        if (!comment.getAuthor().getUsername().equals(principal.getName())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "삭제권한이 없습니다.");
        }
        commentService.delete(comment);

        return new ResponseDto<>(HttpStatus.OK.value(), "댓글 삭제 완료");
    }

    @GetMapping("/recent")
    public ResponseDto<List<CommentDto>> getRecentComments() {
        List<Comment> comments = commentService.getRecentComments();

        return new ResponseDto<>(
                comments.stream()
                        .map(CommentDto::new)
                        .collect(Collectors.toList())
        );
    }
}
