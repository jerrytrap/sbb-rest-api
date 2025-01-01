'use client';
import { useEffect, useState } from 'react';

export default function Home() {
  const [questions, setQuestions] = useState([]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await fetch("http://localhost:8080/question/list?category_id=1");
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
  }, []);

  return (
      <div>
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
                    <td>{question.subject}</td>
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
