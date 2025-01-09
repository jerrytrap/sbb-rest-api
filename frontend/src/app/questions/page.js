"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

export default function Home() {
  const router = useRouter();
  const [currentPage, setCurrentPage] = useState(0);
  const [questions, setQuestions] = useState([]);
  const [totalQuestions, setTotalQuestions] = useState(0);
  const [isLogin, setIsLogin] = useState(false);
  const [keyword, setKeyword] = useState("");
  const [categories, setCategories] = useState([]);
  const [category, setCategory] = useState({
    id: 1,
    name: "질문답변",
  });

  useEffect(() => {
    fetchQuestions();
  }, [currentPage, category]);

  useEffect(() => {
    checkLogin();
    fetchCategories();
  }, []);

  const fetchQuestions = async () => {
    try {
      const response = await fetch(
        `http://localhost:8080/api/v1/questions?page=${currentPage}&kw=${keyword}&category_id=${category.id}`
      );
      const result = await response.json();

      setQuestions(result.data.content);
      setTotalQuestions(result.data.totalPages);
    } catch (error) {
      throw new Error("Error fetching data:", error);
    }
  };

  const fetchCategories = async () => {
    try {
      const response = await fetch(`http://localhost:8080/api/v1/categories`);
      if (!response.ok) {
        throw new Error("Failed to fetch");
      }
      const result = await response.json();
      setCategories(result);
    } catch (error) {
      throw new Error("Error fetching data:", error);
    }
  };

  const handleCategoryChange = (e) => {
    const categoryName = e.target.innerText;
    setCategory(categories.find((category) => category.name === categoryName));
  };

  const handleLogout = async (e) => {
    e.preventDefault();
    await fetch("http://localhost:8080/user/logout", {
      method: "POST",
      credentials: "include",
    });
    checkLogin();
  };

  const checkLogin = () => {
    fetch("http://localhost:8080/user/status", {
      method: "GET",
      credentials: "include",
    })
      .then((response) => {
        return response.json();
      })
      .then((data) => {
        if (data.code === 200) {
          setIsLogin(true);
        } else if (data.code === 401) {
          setIsLogin(false);
        }
      });
  };

  const showDetail = (e, question) => {
    e.preventDefault();
    router.push(`/questions/detail/${question.id}`);
  };

  const handlePageChange = (page) => {
    setCurrentPage(page);
  };

  return (
    <div className="max-w-7xl mx-auto p-6">
      <div className="flex justify-start space-x-4 mb-6">
        {isLogin ? (
          <div>
            <a
              href="#"
              onClick={handleLogout}
              className="text-blue-600 hover:text-blue-800 font-semibold mr-4"
            >
              로그아웃
            </a>
            <a
              href="/user/info"
              className="text-blue-600 hover:text-blue-800 font-semibold"
            >
              회원정보
            </a>
          </div>
        ) : (
          <div className="space-x-4">
            <a
              href="/user/signup"
              className="text-blue-600 hover:text-blue-800 font-semibold"
            >
              회원가입
            </a>
            <a
              href="/user/login"
              className="text-blue-600 hover:text-blue-800 font-semibold"
            >
              로그인
            </a>
            <a
              href="http://localhost:8080/oauth2/authorization/google"
              className="text-blue-600 hover:text-blue-800 font-semibold"
            >
              구글로그인
            </a>
          </div>
        )}
      </div>

      <div className="my-4">
        <div className="flex justify-between items-center">
          <div className="flex flex-wrap gap-2">
            {categories.map((c, index) => (
              <button
                key={index}
                onClick={handleCategoryChange}
                className={`px-4 py-2 border border-gray-300 rounded-sm text-sm font-medium ${
                  category.id === c.id
                    ? "bg-blue-600 text-white disabled:"
                    : "bg-white text-black hover:bg-gray-100"
                }`}
              >
                {c.name}
              </button>
            ))}
          </div>
          <div className="space-x-4">
            <a
              href="/answers/recent"
              className="text-blue-600 hover:text-blue-800 font-semibold"
            >
              최근 답변
            </a>
            <a
              href="/comments/recent"
              className="text-blue-600 hover:text-blue-800 font-semibold"
            >
              최근 댓글
            </a>
          </div>
        </div>
      </div>
      <div className="w-full sm:w-1/2 flex justify-between mb-4 mr-4">
        <a
          href={`/questions/create/${category.id}`}
          className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition"
        >
          질문 등록하기
        </a>

        <div className="flex items-center space-x-2">
          <input
            type="text"
            id="search_kw"
            value={keyword}
            onChange={(e) => setKeyword(e.target.value)}
            className="w-full sm:w-64 px-4 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          <button
            onClick={fetchQuestions}
            className="px-4 py-2 bg-blue-500 text-white border border-blue-500 rounded-md hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
            type="button"
            id="btn_search"
          >
            찾기
          </button>
        </div>
      </div>

      <table className="min-w-full table-auto border-collapse">
        <thead>
          <tr className="bg-gray-100 text-gray-700">
            <th className="px-4 py-2 text-left">번호</th>
            <th className="px-4 py-2 text-left">제목</th>
            <th className="px-4 py-2 text-left">글쓴이</th>
            <th className="px-4 py-2 text-left">작성일시</th>
            <th className="px-4 py-2 text-left">조회수</th>
          </tr>
        </thead>
        <tbody>
          {questions.map((question) => (
            <tr key={question.id} className="border-t hover:bg-gray-50">
              <td className="px-4 py-2">{question.id}</td>
              <td className="px-4 py-2">
                <a
                  href="#"
                  onClick={(e) => showDetail(e, question)}
                  className="text-blue-600 hover:text-blue-800"
                >
                  {question.subject}
                </a>
                <span className="text-red-500 text-sm ml-2">
                  {question.answerCount}
                </span>
              </td>
              <td className="px-4 py-2">{question.authorName}</td>
              <td className="px-4 py-2">
                {new Date(question.createDate).toLocaleDateString()}
              </td>
              <td className="px-4 py-2">{question.viewCount}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className="flex justify-center space-x-2">
        {currentPage > 0 && (
          <button
            onClick={() => handlePageChange(currentPage - 1)}
            className="px-4 py-2 text-sm font-medium border rounded-md hover:bg-gray-200 opacity-80 disabled:cursor-not-allowed disabled:opacity-50"
          >
            이전
          </button>
        )}

        {[...Array(totalQuestions)].map((_, index) => (
          <button
            key={index}
            onClick={() => handlePageChange(index)}
            className={`px-4 py-2 text-sm font-medium border rounded-md hover:bg-gray-200 ${
              index === currentPage ? "bg-blue-500 text-white" : "text-gray-700"
            }`}
          >
            {index + 1}
          </button>
        ))}

        {currentPage + 1 < totalQuestions && (
          <button
            onClick={() => handlePageChange(currentPage + 1)}
            className="px-4 py-2 text-sm font-medium border rounded-md hover:bg-gray-200 opacity-80 disabled:cursor-not-allowed disabled:opacity-50"
          >
            다음
          </button>
        )}
      </div>
    </div>
  );
}
