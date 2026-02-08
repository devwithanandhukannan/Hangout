import { useContext, useState } from "react";
import api from "../api/api";
import { AuthContext } from "../context/AuthContext";

export default function Signin() {
  const { setIsAuth } = useContext(AuthContext);
  const [form, setForm] = useState({ username: "", password: "" });

  const submit = async (e) => {
    e.preventDefault();
    try {
      await api.post("/signin", form);
      setIsAuth(true);
      alert("Logged in");
    } catch (err) {
      alert(err.response?.data?.message);
    }
  };

  return (
    <form onSubmit={submit}>
      <h2>Signin</h2>

      <input
        placeholder="Username"
        onChange={(e) => setForm({ ...form, username: e.target.value })}
      />
      <input
        type="password"
        placeholder="Password"
        onChange={(e) => setForm({ ...form, password: e.target.value })}
      />

      <button>Login</button>
    </form>
  );
}
