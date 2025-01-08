'use client';
import {useEffect, useState} from "react";

export default function RecentComments() {
    const [recentComments, setRecentComments] = useState([]);

    useEffect(() => {
        fetchComments();
    }, []);

    const fetchComments = async () => {
        try {
            const response = await fetch('http://localhost:8080/api/v1/comment/recent', {
                method: 'GET',
            });
            if (!response.ok) {
                throw new Error("Failed to fetch");
            }

            const result = await response.json();
            setRecentComments(result);
        } catch (error) {
            console.error("Error fetching data:", error);
        }
    };

    return (
        <div className="container mx-auto px-4">
            <h5 className="my-3 border-b pb-2 text-lg font-semibold">최근 댓글</h5>
            <table className="table-auto w-full border-collapse">
                <thead className="bg-gray-800 text-white">
                <tr className="text-center">
                    <th className="px-4 py-2">내용</th>
                    <th className="px-4 py-2">작성일시</th>
                </tr>
                </thead>
                <tbody>
                {recentComments.map((comment) =>
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