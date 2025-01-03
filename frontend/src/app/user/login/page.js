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

        const response = await fetch("http://localhost:8080/user/login", {
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
            localStorage.setItem("jwtToken", data.data.token);
            await router.replace("/");
        }
    };

    return (
        <div>
            <form onSubmit={requestLogin} method="post">
                <div>
                    <label htmlFor="username" className="form-label">사용자ID</label>
                    <input type="text" name="username" className="form-control"/>
                </div>
                <div>
                    <label htmlFor="password" className="form-label">비밀번호</label>
                    <input type="password" name="password" className="form-control"/>
                </div>
                <button type="submit">로그인</button>
            </form>
            <span><a href="">비밀번호를 분실했어요.</a></span>
        </div>
    );
}