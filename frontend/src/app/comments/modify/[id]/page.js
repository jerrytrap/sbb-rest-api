"use client";

import { useParams, useRouter } from "next/navigation";
import { useEffect, useState } from "react";

export default function CommentModifyForm() {
  const params = useParams();
  const router = useRouter();
  const [commentContent, setCommentContent] = useState("");

  const handleChange = (e) => {
    setCommentContent(e.target.value);
  };

  useEffect(() => {
    getOldData();
  }, []);

  const submitComment = (e) => {
    e.preventDefault();
    const comment = { content: commentContent };

    fetch("http://localhost:8080/api/v1/comment/" + params.id, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(comment),
      credentials: "include",
    }).then((response) => {
      if (response.status === 200) {
        router.back();
      } else if (response.status === 401) {
        router.replace("/user/login");
      }
    });
  };

  const getOldData = async () => {
    try {
      const response = await fetch(
        "http://localhost:8080/api/v1/comment/" + params.id
      );
      if (!response.ok) {
        throw new Error("Failed to fetch");
      }
      const result = await response.text();
      setCommentContent(result);
    } catch (error) {
      throw new Error("Error fetching data:", error);
    }
  };

  return (
    <div className="m-4">
      <h5>댓글 수정</h5>
      <form onSubmit={submitComment}>
        <div className="mb-4">
          <label
            htmlFor="content"
            className="block text-sm font-medium text-gray-700"
          >
            내용
          </label>
          <textarea
            id="content"
            name="content"
            className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
            rows="10"
            value={commentContent}
            onChange={handleChange}
            required
          ></textarea>
        </div>

        <input
          type="submit"
          value="저장하기"
          className="w-full mt-4 px-4 py-2 bg-blue-500 text-white rounded-md hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-400"
        />
      </form>
    </div>
  );
}
