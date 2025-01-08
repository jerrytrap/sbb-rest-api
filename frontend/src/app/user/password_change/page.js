'use client';
import {useRouter} from "next/navigation";

export default function Login() {
    const router = useRouter();

    const changePassword = async (e) => {
        const formData = {
            "currentPassword": e.target.currentPassword.value,
            "newPassword": e.target.newPassword.value,
        };
        e.preventDefault();

        const response = await fetch("http://localhost:8080/user/password_change", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify(formData),
            credentials: 'include'
        })

        if (response.status === 200) {
            alert("비밀번호를 변경했습니다.")
            await fetch("http://localhost:8080/user/logout", {
                method: 'POST',
                credentials: 'include'
            });
            await router.replace("/");
        } else {
            alert("비밀번호를 다시 확인해주세요.");
        }
    };

    return (
        <div className="max-w-sm mx-auto p-6 border rounded-lg shadow-lg">
            <form onSubmit={changePassword} method="post" className="space-y-4">
                <div className="mb-4">
                    <label htmlFor="currentPassword" className="block text-lg font-medium text-gray-700">현재 비밀번호</label>
                    <input
                        type="password"
                        name="currentPassword"
                        className="form-control w-full p-3 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                </div>

                <div className="mb-4">
                    <label htmlFor="newPassword" className="block text-lg font-medium text-gray-700">새 비밀번호</label>
                    <input
                        type="password"
                        name="newPassword"
                        className="form-control w-full p-3 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                </div>

                <button
                    type="submit"
                    className="w-full bg-blue-500 text-white py-3 rounded-md shadow-md hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-400"
                >
                    비밀번호 변경
                </button>
            </form>
        </div>
    );
}