'use client';

import {useRouter} from "next/navigation";

export default function Signup() {
    const router = useRouter();

    const requestSignup = async (e) => {
        const formData = {
            username: e.target.username.value,
            password1: e.target.password1.value,
            password2: e.target.password2.value,
            email: e.target.email.value
        };
        e.preventDefault();

        const response = await fetch("http://localhost:8080/user/signup", {
            method: "POST",
            headers: {
                'Content-type': 'application/json'
            },
            body: JSON.stringify(formData),
            credentials: "include"
        });

        const data = await response.json();
        alert(data.message);

        if (response.ok) {
            await router.replace("/");
        }
    };

    return (
        <div className="container mx-auto my-8 p-6 border rounded-lg shadow-lg">
            <div className="text-center mb-6">
                <h4 className="text-2xl font-semibold">회원가입</h4>
            </div>
            <form onSubmit={requestSignup} method="POST" className="space-y-4">
                <div className="mb-4">
                    <label htmlFor="username" className="block text-lg font-medium text-gray-700">사용자ID</label>
                    <input
                        type="text"
                        className="form-control w-full p-3 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                        name="username"
                    />
                </div>
                <div className="mb-4">
                    <label htmlFor="password1" className="block text-lg font-medium text-gray-700">비밀번호</label>
                    <input
                        type="password"
                        className="form-control w-full p-3 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                        name="password1"
                    />
                </div>
                <div className="mb-4">
                    <label htmlFor="password2" className="block text-lg font-medium text-gray-700">비밀번호 확인</label>
                    <input
                        type="password"
                        className="form-control w-full p-3 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                        name="password2"
                    />
                </div>
                <div className="mb-4">
                    <label htmlFor="email" className="block text-lg font-medium text-gray-700">이메일</label>
                    <input
                        type="email"
                        className="form-control w-full p-3 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                        name="email"
                    />
                </div>
                <button
                    type="submit"
                    className="w-full bg-blue-500 text-white py-3 rounded-md shadow-md hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-400"
                >
                    회원가입
                </button>
            </form>
        </div>
    );
}