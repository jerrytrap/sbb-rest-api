'use client';
import {useParams, useRouter} from "next/navigation";
import {useEffect, useState} from "react";

export default function QuestionDetail() {
    const params = useParams();
    const router = useRouter();
    const [question, setQuestion] = useState({"comments": []});
    const [username, setUsername] = useState("");
    const [answerContent, setAnswerContent] = useState("");
    const [answers, setAnswers] = useState([]);
    const [totalPages, setTotalPages] = useState(0);
    const [totalAnswers, setTotalAnswers] = useState(0);
    const [currentPage, setCurrentPage] = useState(0);
    const [order, setOrder] = useState("createDate");

    useEffect(() => {
        fetchQuestion();
        fetchAnswers();
        getUsername();
    }, []);

    useEffect(() => {
        fetchAnswers();
    }, [currentPage, order]);

    const fetchQuestion = async () => {
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

    const deleteAnswer = (e, id) => {
        e.preventDefault();
        const isConfirmed = confirm("정말 삭제하시겠습니까?");

        if (isConfirmed) {
            fetch("http://localhost:8080/api/v1/answers/" + id, {
                method: 'DELETE',
                credentials: 'include'
            }).then((result) => {
                if (result.status === 200) {
                    fetchAnswers();
                }
            });
        }
    }

    const deleteComment = (e, id, type) => {
        e.preventDefault();
        const isConfirmed = confirm("정말 삭제하시겠습니까?");

        if (isConfirmed) {
            fetch("http://localhost:8080/api/v1/comment/" + id, {
                method: 'DELETE',
                credentials: 'include'
            }).then((result) => {
                if (result.status === 200) {
                    if (type === "question") {
                        fetchQuestion();
                    } else if (type === "answer") {
                        fetchAnswers();
                    }
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
                fetchQuestion();
            }
        });
    }

    const voteAnswer = (e, id) => {
        e.preventDefault();
        fetch("http://localhost:8080/api/v1/answers/vote/" + id, {
            method: 'GET',
            credentials: 'include'
        }).then((result) => {
            if (result.status === 200) {
                fetchAnswers();
            }
        });
    }

    const fetchAnswers = async () => {
        try {
            const response = await fetch(`http://localhost:8080/api/v1/answers?question_id=${params.id}&page=${currentPage}&sort=${order}`);
            if (!response.ok) {
                throw new Error("Failed to fetch");
            }
            const result = await response.json();

            setAnswers(result.content);
            setTotalPages(result.totalPages);
            setTotalAnswers(result.totalElements);
        } catch (error) {
            throw new Error("Error fetching data:", error);
        }
    }

    const createAnswer = (e) => {
        e.preventDefault();
        const answer = {"content": answerContent};

        fetch("http://localhost:8080/api/v1/answers?question_id=" + params.id, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(answer),
            credentials: 'include'
        }).then((result) => {
            if (result.status === 201) {
                setAnswerContent("");
                fetchAnswers();
            }
        });
    }

    const addQuestionComment = (e) => {
        e.preventDefault();
        const content = e.target.elements.content.value

        const comment = {
            "content": content,
            "questionId": params.id
        };

        fetch("http://localhost:8080/api/v1/comment", {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(comment),
            credentials: 'include'
        }).then((result) => {
            if (result.status === 201) {
                fetchQuestionComment();
            }
        });
    }

    const addAnswerComment = (e, id) => {
        e.preventDefault();
        const content = e.target.elements.content.value

        const comment = {
            "content": content,
            "answerId": parseInt(id)
        };

        fetch("http://localhost:8080/api/v1/comment/answer", {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(comment),
            credentials: 'include'
        }).then((result) => {
            if (result.status === 201) {
                fetchAnswers();
            }
        });
    }

    const handlePageChange = (page) => {
        setCurrentPage(page)
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

                    <hr/>
                    <div className="space-y-4">
                        <div className="space-y-2">
                            {question.comments.map((comment) => (
                                    <div className="flex justify-between items-center" key={comment.id}>
                                        <div className="text-sm text-gray-700">
                                            <p className="font-medium">{comment.content}</p>
                                            <span className="text-xs text-gray-500">{comment.authorName}</span>
                                            <span
                                                className="text-xs text-gray-500 ml-2">{new Date(comment.createDate).toLocaleString()}</span>
                                        </div>
                                        <div className="space-x-2">
                                            <a href={`/comments/modify/${comment.id}`}
                                               className="px-4 py-2 text-sm text-blue-600 border border-blue-600 hover:bg-blue-100 rounded-md">
                                                수정
                                            </a>
                                            <a href="#"
                                               className="px-4 py-2 text-sm text-red-600 border border-red-600 hover:bg-red-100 rounded-md"
                                               onClick={(e) => deleteComment(e, comment.id, "question")}>
                                                삭제
                                            </a>
                                        </div>
                                        <hr className="border-t border-gray-200"/>
                                    </div>
                                )
                            )}
                        </div>

                        <div className="mt-4 space-y-4">
                            <form onSubmit={addQuestionComment} className="space-y-4">
                                <input type="text"
                                       className="w-full p-2 border border-gray-300 rounded-md text-gray-500"
                                       placeholder={username !== "" ? '답변을 작성하세요' : '로그인이 필요합니다.'}
                                       name="content"
                                       disabled={username === ""}
                                       required/>

                                <button type="submit"
                                        disabled={username === ""}
                                        className="w-full py-2 px-4 bg-blue-600 text-white rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500">
                                    등록
                                </button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>

            <h5 className="border-bottom my-3 py-2">{totalAnswers + "개의 답변이 있습니다."}</h5>

            <select id="select_order" value={order} onChange={(e) => setOrder(e.target.value)}
                    className="block w-full p-2.5 border border-gray-300 rounded-md bg-white text-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all">
                <option value="createDate" data-order="createDate">최신순</option>
                <option value="voter" data-order="voter">추천순</option>
            </select>

            {answers.map((answer) => (
                <div key={answer.id} className="card my-3">
                    <div className="my-3 border rounded-lg shadow-md bg-white p-4">
                        <div className="card-text mb-4">{answer.content}</div>
                        <div className="flex justify-end space-x-4">
                            {answer.modifyDate && (
                                <div className="badge bg-light text-dark p-2 rounded-md shadow-md">
                                    <div className="mb-2">modified at</div>
                                    <div>{new Date(answer.modifyDate).toLocaleString()}</div>
                                </div>
                            )}
                            <div className="badge bg-light text-dark p-2 rounded-md shadow-md">
                                <div className="mb-2">
                                    {answer.authorName}
                                </div>
                                <div>{new Date(answer.createDate).toLocaleString()}</div>
                            </div>
                        </div>

                        <div className="my-3 flex space-x-3">
                            <a href="#"
                               className="px-4 py-2 text-sm border border-gray-300 text-gray-700 hover:bg-gray-100 rounded-md"
                               onClick={(e) => voteAnswer(e, answer.id)}>
                                추천
                                <span
                                    className="rounded-full bg-green-500 text-white ml-2 px-2 py-1 text-xs">{answer.voterCount}</span>
                            </a>
                            {answer.authorName === username && (
                                <>
                                    <a href={`/answers/modify/${answer.id}`}
                                       className="px-4 py-2 text-sm text-blue-600 border border-blue-600 hover:bg-blue-100 rounded-md">
                                        수정
                                    </a>
                                    <a href="#"
                                       className="px-4 py-2 text-sm text-red-600 border border-red-600 hover:bg-red-100 rounded-md"
                                       onClick={(e) => deleteAnswer(e, answer.id)}
                                    >
                                        삭제
                                    </a>
                                </>
                            )}
                        </div>
                        <hr/>
                        <div className="space-y-4">
                            <div className="space-y-2">
                                {answer.comments.map((comment) => (
                                        <div className="flex justify-between items-center" key={comment.id}>
                                            <div className="text-sm text-gray-700">
                                                <p className="font-medium">{comment.content}</p>
                                                <span className="text-xs text-gray-500">{comment.authorName}</span>
                                                <span
                                                    className="text-xs text-gray-500 ml-2">{new Date(comment.createDate).toLocaleString()}</span>
                                            </div>
                                            <div className="space-x-2">
                                                <a href={`/comments/modify/${comment.id}`}
                                                   className="px-4 py-2 text-sm text-blue-600 border border-blue-600 hover:bg-blue-100 rounded-md">
                                                    수정
                                                </a>
                                                <a onClick={(e) => deleteComment(e, comment.id, "answer")}
                                                   className="px-4 py-2 text-sm text-red-600 border border-red-600 hover:bg-red-100 rounded-md">
                                                    삭제
                                                </a>
                                            </div>
                                            <hr className="border-t border-gray-200"/>
                                        </div>
                                    )
                                )}
                            </div>

                            <div className="mt-4 space-y-4">
                                <form onSubmit={(e) => addAnswerComment(e, answer.id)} className="space-y-4">
                                    <input type="text"
                                           className="w-full p-2 border border-gray-300 rounded-md text-gray-500"
                                           placeholder={username !== "" ? '답변을 작성하세요' : '로그인이 필요합니다.'}
                                           name="content"
                                           disabled={username === ""}
                                           required/>

                                    <button type="submit"
                                            disabled={username === ""}
                                            className="w-full py-2 px-4 bg-blue-600 text-white rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500">
                                        등록
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
            ))}

            <div className="flex justify-center space-x-2">
                {currentPage > 0 && (
                    <button
                        onClick={() => handlePageChange(currentPage - 1)}
                        className="px-4 py-2 text-sm font-medium border rounded-md hover:bg-gray-200 opacity-80 disabled:cursor-not-allowed disabled:opacity-50"
                    >이전</button>
                )}

                {[...Array(totalPages)].map((_, index) => (
                    <button
                        key={index}
                        onClick={() => handlePageChange(index)}
                        className={`px-4 py-2 text-sm font-medium border rounded-md hover:bg-gray-200 ${index === currentPage ? 'bg-blue-500 text-white' : 'text-gray-700'}`}
                    >
                        {index + 1}
                    </button>
                ))}

                {currentPage + 1 < totalPages && (
                    <button
                        onClick={() => handlePageChange(currentPage + 1)}
                        className="px-4 py-2 text-sm font-medium border rounded-md hover:bg-gray-200 opacity-80 disabled:cursor-not-allowed disabled:opacity-50"
                    >다음</button>
                )}
            </div>

            <div className="my-3">
                <form onSubmit={createAnswer}>
                    <div className="mb-3">
                        <textarea
                            value={answerContent}
                            onChange={(e) => setAnswerContent(e.target.value)}
                            rows="10"
                            className="form-control w-full p-3 border rounded-md"
                            placeholder={username !== "" ? '답변을 작성하세요' : '로그인이 필요합니다.'}
                            disabled={username === ""}
                            required
                        />
                    </div>

                    <button type="submit"
                            className="btn btn-primary my-2 px-4 py-2 bg-blue-500 text-white rounded-lg disabled:bg-gray-300"
                            disabled={username === ""}>
                        답변 등록
                    </button>
                </form>
            </div>
        </div>
    );
}