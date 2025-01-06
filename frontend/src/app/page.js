'use client';
import { useEffect, useState } from 'react';
import { useRouter } from "next/navigation";

export default function Home() {
  const router = useRouter();
  const [questions, setQuestions] = useState([]);
  const [isLogin, setIsLogin] = useState(false);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const defaultCategoryId = 1;
        const response = await fetch("http://localhost:8080/api/v1/questions");
        if (!response.ok) {
          throw new Error("Failed to fetch");
        }
        const result = await response.json();
        setQuestions(result);
      } catch (error) {
        throw new Error("Error fetching data:", error);
      }
    };

    fetchData();
    checkLogin();
  }, []);

  const handleLogout = async (e) => {
    e.preventDefault();
    await fetch("http://localhost:8080/user/logout", {
      method: 'POST',
      credentials: 'include'
    });
    checkLogin();
  }

  const checkLogin = () => {
    fetch("http://localhost:8080/user/status", {
      method: 'GET',
      credentials: 'include'
    }).then((result) => {
      if (result.status === 200) {
        setIsLogin(true);
      } else if (result.status === 401) {
        setIsLogin(false);
      }
    });
  }

  const showDetail = (e, question) => {
    e.preventDefault();
    router.push(`/questions/detail/${question.id}`)
  }

  return (
      <div>
        <div>
          {isLogin ?
              <div>
                <a href="#" onClick={handleLogout}>로그아웃</a>
              </div>
              :
              <div>
                <a href="/user/signup">회원가입</a>
                <a href="/user/login">로그인</a>
              </div>
          }
        </div>
        <div>
          <a href="/questions/create">질문 등록하기</a>
        </div>
        <table>
          <thead>
          <tr>
            <th>번호</th>
            <th>제목</th>
            <th>글쓴이</th>
            <th>작성일시</th>
            <th>조회수</th>
          </tr>
          </thead>
          <tbody>
          {questions.map((question) => (
              <tr key={question.id}>
                <td>{question.id}</td>
                <td><a href="#" onClick={(e) => showDetail(e, question)}>{question.subject}</a></td>
                <td>{question.authorName}</td>
                <td>{question.createDate}</td>
                <td>{question.voterCount}</td>
              </tr>
          ))}
          </tbody>
        </table>
      </div>
  );
}
