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
        <div>
            <h5>질문 등록</h5>
            <form onSubmit={submitQuestion}>
                <div className="mb-3">
                    <label htmlFor="subject" className="form-label">제목</label>
                    <input type="text" name="subject" className="form-control" required/>
                </div>
                <div className="mb-3">
                    <label htmlFor="content" className="form-label">내용</label>
                    <textarea id="content" name="content" className="form-control" rows="10" required></textarea>
                </div>
                <input type="submit" value="저장하기"/>
            </form>
        </div>
    )
}