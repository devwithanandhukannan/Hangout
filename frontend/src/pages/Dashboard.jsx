import api from "../api/api";

export default function Dashboard() {
  const followUser = async (fromUserId, toUserId) => {
    try {
      const res = await api.patch("/follow", {
        fromUserId,
        toUserId,
      });
      alert(JSON.stringify(res.data));
    } catch (err) {
      alert(err.response?.data?.message);
    }
  };

  const rankUser = async (stranger_id) => {
    try {
      const res = await api.post("/rank", { stranger_id });
      alert(`Rank: ${res.data.rank}`);
    } catch (err) {
      alert(err.response?.data?.message);
    }
  };

  return (
    <div>
      <h2>Dashboard</h2>

      <button onClick={() => followUser(1, 2)}>
        Follow User 2
      </button>

      <button onClick={() => rankUser(2)}>
        Rank User 2
      </button>
    </div>
  );
}
