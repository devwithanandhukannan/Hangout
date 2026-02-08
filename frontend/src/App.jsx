import Signup from "./auth/Signup";
import Signin from "./auth/Signin";
import Dashboard from "./pages/Dashboard";
import Chat from "./pages/Chat";

export default function App() {
  return (
    <>
      <Signup />
      <Signin />
      <Dashboard />
      <Chat />
    </>
  );
}
