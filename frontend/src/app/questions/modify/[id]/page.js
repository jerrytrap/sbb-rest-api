'use client';

import {useParams, useRouter} from "next/navigation";
import {useEffect, useState} from "react";

export default function QuestionModifyForm() {
    const params = useParams();
    const router = useRouter();
    const [formData, setFormData] = useState({
        subject: '',
        content: ''
    });

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData((prevData) => ({
            ...prevData,
            [name]: value
        }));
    };

    useEffect(() => {
        getOldData();
    }, []);

    const submitQuestion = (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);

        fetch("http://localhost:8080/api/v1/questions/" + params.id, {
            method: "PATCH",
            body: formData,
            credentials: 'include'
        }).then((response) => {
            if (response.status === 200) {
                router.replace("/");
            } else if (response.status === 401) {
                router.replace("/user/login");
            }
        });
    };

    const getOldData = async () => {
        try {
            const response = await fetch("http://localhost:8080/api/v1/questions/" + params.id);
            if (!response.ok) {
                throw new Error("Failed to fetch");
            }
            const result = await response.json();
            setFormData({
                subject: result.subject,
                content: result.content
            })
        } catch (error) {
            throw new Error("Error fetching data:", error);
        }
    }

    return (
        <div className="m-4">
            <h5>질문 수정</h5>
            <form onSubmit={submitQuestion}>
                <div className="mb-4">
                    <label htmlFor="subject" className="block text-sm font-medium text-gray-700">제목</label>
                    <input
                        type="text"
                        name="subject"
                        className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                        value={formData.subject}
                        onChange={handleChange}
                        required
                    />
                </div>

                <div className="mb-4">
                    <label htmlFor="content" className="block text-sm font-medium text-gray-700">내용</label>
                    <textarea
                        id="content"
                        name="content"
                        className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                        rows="10"
                        value={formData.content}
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
    )
}