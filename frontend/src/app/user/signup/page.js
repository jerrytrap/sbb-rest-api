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
        <div>
            <div>
                <div>
                    <h4>회원가입</h4>
                </div>
            </div>
            <form onSubmit={requestSignup} method="POST">
                <div className="mb-3">
                    <label htmlFor="username" className="form-label">사용자ID</label>
                    <input type="text" className="form-control" name="username" />
                </div>
                <div className="mb-3">
                    <label htmlFor="password1" className="form-label">비밀번호</label>
                    <input type="password" className="form-control" name="password1" />
                </div>
                <div className="mb-3">
                    <label htmlFor="password2" className="form-label">비밀번호 확인</label>
                    <input type="password" className="form-control" name="password2" />
                </div>
                <div className="mb-3">
                    <label htmlFor="email" className="form-label">이메일</label>
                    <input type="email" className="form-control" name="email" />
                </div>
                <button type="submit" className="btn btn-primary">회원가입</button>
            </form>
        </div>
    );
}