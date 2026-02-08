import { useState } from "react";
import api from "../api/api";

export default function Signup() {
  const [form, setForm] = useState({
    username: "",
    email: "",
    password: "",
  });

  const submit = async (e) => {
    e.preventDefault();
    try {
      await api.post("/signup", form);
      alert("Account created");
    } catch (err) {
      alert(err.response?.data?.message);
    }
  };

  return (
    <form onSubmit={submit}>
      <h2>Signup</h2>

      <input
        placeholder="Username"
        onChange={(e) => setForm({ ...form, username: e.target.value })}
      />
      <input
        placeholder="Email"
        onChange={(e) => setForm({ ...form, email: e.target.value })}
      />
      <input
        type="password"
        placeholder="Password"
        onChange={(e) => setForm({ ...form, password: e.target.value })}
      />

      <button>Create Account</button>
    </form>
  );
}
