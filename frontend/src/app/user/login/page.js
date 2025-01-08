'use client';
import {useRouter} from "next/navigation";

export default function Login() {
    const router = useRouter();

    const requestLogin = async (e) => {
        const formData = {
            username: e.target.username.value,
            password: e.target.password.value,
        };
        e.preventDefault();

        const urlEncodedData = new URLSearchParams(formData).toString();

        const response = await fetch("http://localhost:8080/api/login", {
            method: "POST",
            headers: {
                'Content-type': 'application/x-www-form-urlencoded'
            },
            body: urlEncodedData,
            credentials: 'include'
        })

        if (response.status === 200) {
            await router.replace("/");
        } else {
            alert("아이디와 비밀번호를 다시 확인해주세요.")
        }
    };

    return (
        <div className="max-w-sm mx-auto p-6 border rounded-lg shadow-lg">
            <form onSubmit={requestLogin} method="post" className="space-y-4">
                <div className="mb-4">
                    <label htmlFor="username" className="block text-lg font-medium text-gray-700">사용자ID</label>
                    <input
                        type="text"
                        name="username"
                        className="form-control w-full p-3 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                </div>

                <div className="mb-4">
                    <label htmlFor="password" className="block text-lg font-medium text-gray-700">비밀번호</label>
                    <input
                        type="password"
                        name="password"
                        className="form-control w-full p-3 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                </div>

                <button
                    type="submit"
                    className="w-full bg-blue-500 text-white py-3 rounded-md shadow-md hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-400"
                >
                    로그인
                </button>
            </form>

            <div className="mt-4 text-center">
                <span className="text-sm text-blue-500 hover:underline"><a href="/user/find_password">비밀번호를 분실했어요.</a></span>
            </div>
        </div>
    );
}