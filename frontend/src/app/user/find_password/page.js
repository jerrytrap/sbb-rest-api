"use client";
import { useRouter } from "next/navigation";
import { useEffect } from "react";

export default function FindPasswordForm() {
  const router = useRouter();

  const sendEmail = (e) => {
    e.preventDefault();

    fetch("http://localhost:8080/user/email", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: e.target.email.value }),
      credentials: "include",
    })
      .then((response) => {
        return response.json();
      })
      .then((data) => {
        if (data.code === 200) {
          alert("임시 비밀번호를 전송했습니다.");
          router.replace("/");
        } else if (data.code === 404) {
          alert("등록되지 않은 이메일입니다.");
        }
      });
  };

  return (
    <div className="max-w-sm mx-auto p-6 border rounded-lg shadow-lg">
      <form onSubmit={sendEmail} className="space-y-4">
        <div className="mb-4">
          <label
            htmlFor="email"
            className="block text-lg font-medium text-gray-700"
          >
            이메일
          </label>
          <input
            type="email"
            name="email"
            className="form-control w-full p-3 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <button
          type="submit"
          className="w-full bg-blue-500 text-white py-3 rounded-md shadow-md hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-400"
        >
          임시 비밀번호 전송
        </button>
      </form>
    </div>
  );
}
