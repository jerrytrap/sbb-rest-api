'use client';

import {useEffect, useState} from "react";

export default function UserInfo() {
    const [userInfo, setUserInfo] = useState("");
    const [questions, setQuestions] = useState([]);
    const [answers, setAnswers] = useState([]);
    const [comments, setComments] = useState([]);

    useEffect(() => {
        getUsername();
    }, []);

    useEffect(() => {
        if (userInfo) {
            fetchQuestions();
            fetchAnswers();
            fetchComments();
        }
    }, [userInfo]);

    const getUsername = async () => {
        try {
            const response = await fetch('http://localhost:8080/user', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                credentials: 'include'
            });
            if (!response.ok) {
                throw new Error("Failed to fetch");
            }

            const result = await response.json();
            setUserInfo(result.data);
        } catch (error) {
            console.error("Error fetching data:", error);
        }
    }

    const fetchQuestions = async () => {
        try {
            const response = await fetch('http://localhost:8080/user/questions', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username: userInfo.username}),
                credentials: 'include'
            });
            if (!response.ok) {
                throw new Error("Failed to fetch");
            }

            const result = await response.json();
            setQuestions(result);
        } catch (error) {
            console.error("Error fetching data:", error);
        }
    };

    const fetchAnswers = async () => {
        try {
            const response = await fetch('http://localhost:8080/user/answers', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username: userInfo.username}),
                credentials: 'include'
            });
            if (!response.ok) {
                throw new Error("Failed to fetch");
            }

            const result = await response.json();
            setAnswers(result);
        } catch (error) {
            console.error("Error fetching data:", error);
        }
    };

    const fetchComments = async () => {
        try {
            const response = await fetch('http://localhost:8080/user/comments', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username: userInfo.username}),
                credentials: 'include'
            });
            if (!response.ok) {
                throw new Error("Failed to fetch");
            }

            const result = await response.json();
            setComments(result);
        } catch (error) {
            console.error("Error fetching data:", error);
        }
    };

    return (
        <div className="container mx-auto px-4">
            <h5 className="my-3 border-b pb-2 text-lg font-semibold">회원 정보</h5>
            <div className="mb-4">
                <ul className="space-y-2">
                    <li className="text-gray-700"><strong>이름:</strong>{userInfo.username}</li>
                    <li className="text-gray-700"><strong>이메일:</strong>{userInfo.email}</li>
                </ul>
            </div>
            <div>
                <a href="/user/password_change" className="text-blue-500 hover:underline">비밀번호 변경</a>
            </div>

            <h5 className="my-3 border-b pb-2 text-lg font-semibold">내가 질문한 글</h5>
            <table className="table-auto w-full border-collapse">
                <thead className="bg-gray-800 text-white">
                <tr className="text-center">
                    <th className="px-4 py-2">질문 번호</th>
                    <th className="px-4 py-2">제목</th>
                    <th className="px-4 py-2">내용</th>
                    <th className="px-4 py-2">작성일시</th>
                </tr>
                </thead>
                <tbody>
                {questions.length > 0 && questions.map((question) =>
                    <tr key={question.id} className="text-center">
                        <td className="px-4 py-2">
                            <a href={`/questions/detail/${question.id}`}
                               className="text-blue-500 hover:underline">{question.id}</a>
                        </td>
                        <td className="px-4 py-2">{question.subject}</td>
                        <td className="px-4 py-2">{question.content}</td>
                        <td className="px-4 py-2">{new Date(question.createDate).toLocaleString()}</td>
                    </tr>
                )}
                </tbody>
            </table>

            <h5 className="my-3 border-b pb-2 text-lg font-semibold">내가 답변한 글</h5>
            <table className="table-auto w-full border-collapse">
                <thead className="bg-gray-800 text-white">
                <tr className="text-center">
                    <th className="px-4 py-2">질문 번호</th>
                    <th className="px-4 py-2">내용</th>
                    <th className="px-4 py-2">작성일시</th>
                </tr>
                </thead>
                <tbody>
                {answers.map((answer) =>
                    <tr key={answer.id} className="text-center">
                        <td className="px-4 py-2">
                            <a href={`/questions/detail/${answer.questionId}`}
                               className="text-blue-500 hover:underline">{answer.questionId}</a>
                        </td>
                        <td className="px-4 py-2">{answer.content}</td>
                        <td className="px-4 py-2">{new Date(answer.createDate).toLocaleString()}</td>
                    </tr>
                )}
                </tbody>
            </table>

            <h5 className="my-3 border-b pb-2 text-lg font-semibold">내가 작성한 댓글</h5>
            <table className="table-auto w-full border-collapse">
                <thead className="bg-gray-800 text-white">
                <tr className="text-center">
                    <th className="px-4 py-2">내용</th>
                    <th className="px-4 py-2">작성일시</th>
                </tr>
                </thead>
                <tbody>
                {comments.map((comment) =>
                    <tr key={comment.id} className="text-center">
                        <td className="px-4 py-2">{comment.content}</td>
                        <td className="px-4 py-2">{new Date(comment.createDate).toLocaleString()}</td>
                    </tr>
                )}
                </tbody>
            </table>
        </div>
    );
}