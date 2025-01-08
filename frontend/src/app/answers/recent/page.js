'use client';
import {useEffect, useState} from "react";

export default function RecentAnswers() {
    const [recentAnswers, setRecentAnswers] = useState([]);

    useEffect(() => {
        fetchAnswers();
    }, []);

    const fetchAnswers = async () => {
        try {
            const response = await fetch('http://localhost:8080/api/v1/answers/recent', {
                method: 'GET',
            });
            if (!response.ok) {
                throw new Error("Failed to fetch");
            }

            const result = await response.json();
            setRecentAnswers(result);
        } catch (error) {
            console.error("Error fetching data:", error);
        }
    };

    return (
        <div className="container mx-auto px-4">
            <h5 className="my-3 border-b pb-2 text-lg font-semibold">최근 답변</h5>
            <table className="table-auto w-full border-collapse">
                <thead className="bg-gray-800 text-white">
                <tr className="text-center">
                    <th className="px-4 py-2">질문 번호</th>
                    <th className="px-4 py-2">내용</th>
                    <th className="px-4 py-2">작성일시</th>
                </tr>
                </thead>
                <tbody>
                {recentAnswers.map((answer) =>
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
        </div>

    );
}