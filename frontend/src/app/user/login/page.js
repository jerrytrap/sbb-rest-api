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