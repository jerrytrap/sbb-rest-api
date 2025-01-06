'use client';
import {useParams, useRouter} from "next/navigation";
import {useEffect, useState} from "react";

export default function QuestionDetail() {
    const params = useParams();
    const router = useRouter();
    const [question, setQuestion] = useState({});
    const [username, setUsername] = useState("");

    useEffect(() => {
        fetchData();
        getUsername();
    }, []);

    const fetchData = async () => {
        try {
            const response = await fetch("http://localhost:8080/api/v1/questions/" + params.id);
            if (!response.ok) {
                throw new Error("Failed to fetch");
            }
            const result = await response.json();
            setQuestion(result);
        } catch (error) {
            throw new Error("Error fetching data:", error);
        }
    };

    const getUsername = () => {
        fetch("http://localhost:8080/user/status", {
            method: 'GET',
            credentials: 'include'
        }).then((result) => {
            if (result.status === 200) {
                result.text().then((data) => {
                    setUsername(data);
                })
            }
        });
    }

    const deleteQuestion = (e) => {
        e.preventDefault();
        const isConfirmed = confirm("정말 삭제하시겠습니까?");

        if (isConfirmed) {
            fetch("http://localhost:8080/api/v1/questions/" + params.id, {
                method: 'DELETE',
                credentials: 'include'
            }).then((result) => {
                if (result.status === 200) {
                    router.replace("/");
                }
            });
        }
    }

    const voteQuestion = (e) => {
        e.preventDefault();
        fetch("http://localhost:8080/api/v1/questions/vote/" + params.id, {
            method: 'GET',
            credentials: 'include'
        }).then((result) => {
            if (result.status === 200) {
                fetchData();
            }
        });
    }

    return (
        <div className="m-4">
            <h2 className="border-b-2 py-2 text-xl font-semibold">{question.subject}</h2>
            <div className="my-3 border rounded-lg shadow-md bg-white">
                <div className="p-4">
                    <div className="mb-4">{question.content}</div>
                    <div className="flex justify-end space-x-4">
                        <div className="badge bg-gray-100 text-gray-800 p-2 text-start mx-3 rounded-lg shadow-md">
                            <div className="mb-2">modified at</div>
                            <div>{new Date(question.modifyDate).toLocaleString()}</div>
                        </div>
                        <div className="badge bg-gray-100 text-gray-800 p-2 text-start rounded-lg shadow-md">
                            <div className="mb-2">
                                {question.authorName}
                            </div>
                            <div>{new Date(question.createDate).toLocaleString()}</div>
                        </div>
                    </div>
                    <div className="my-3 flex space-x-3">
                        <a href="#"
                           className="px-4 py-2 text-sm border border-gray-300 text-gray-700 hover:bg-gray-100 rounded-md"
                            onClick={voteQuestion}>
                            추천
                            <span
                                className="rounded-full bg-green-500 text-white ml-2 px-2 py-1 text-xs">{question.voterCount}</span>
                        </a>
                        {question.authorName === username ? (
                            <>
                                <a href={`/questions/modify/${question.id}`}
                                   className="px-4 py-2 text-sm text-blue-600 border border-blue-600 hover:bg-blue-100 rounded-md">
                                    수정
                                </a>
                                <a href="#"
                                   className="px-4 py-2 text-sm text-red-600 border border-red-600 hover:bg-red-100 rounded-md"
                                    onClick={deleteQuestion}>
                                    삭제
                                </a>
                            </>
                        ) : null}
                    </div>
                </div>
            </div>
        </div>
    );
}