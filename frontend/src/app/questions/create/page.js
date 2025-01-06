'use client';

import {useRouter} from "next/navigation";

export default function QuestionCreateForm() {
    const router = useRouter();

    const submitQuestion = (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);

        fetch("http://localhost:8080/api/v1/questions/create", {
            method: "POST",
            body: formData,
            credentials: 'include'
        }).then((response) => {
            if (response.status === 201) {
                router.replace("/");
            } else if (response.status === 401) {
                router.replace("/user/login");
            }
        });
    };

    return (
        <div className="max-w-xl mx-auto p-6 border rounded-lg shadow-lg">
            <h5 className="text-xl font-semibold mb-4">질문 등록</h5>
            <form onSubmit={submitQuestion} className="space-y-4">
                <div className="mb-4">
                    <label htmlFor="subject" className="block text-lg font-medium text-gray-700">제목</label>
                    <input
                        type="text"
                        name="subject"
                        className="w-full p-3 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                        required
                    />
                </div>

                <div className="mb-4">
                    <label htmlFor="content" className="block text-lg font-medium text-gray-700">내용</label>
                    <textarea
                        id="content"
                        name="content"
                        className="w-full p-3 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                        rows="10"
                        required
                    ></textarea>
                </div>

                <button
                    type="submit"
                    className="w-full bg-blue-500 text-white py-3 rounded-md shadow-md hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-400"
                >
                    저장하기
                </button>
            </form>
        </div>
    )
}