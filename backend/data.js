export const user_db = {
  users: new Map(),        // userId -> user
  usernames: new Map(),    // username -> userId
  emails: new Map(),       // email -> userId

  follows: new Map(),      // userId -> Set(userId)
  followers: new Map(),    // userId -> Set(userId)
  friends: new Map(),      // userId -> Set(userId)

  rank: new Map(),         // userId -> { count, voters:Set }
};
export const activeUsers = new Map(); // userId => socketId
export const waitingQueue = []; // array of userIds waiting for a match
export const busyUsers = new Set(); // users currently in a chat
