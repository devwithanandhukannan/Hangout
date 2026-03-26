| Feature                 | Endpoint/Event                         | Description                                      |
|-------------------------|----------------------------------------|--------------------------------------------------|
| Notification System     | GET /notifications                     | Paginated notifications with unread count        |
| Mark Read               | PATCH /notifications/read              | Mark specific or all notifications as read       |
| Clear Notifications     | DELETE /notifications/clear            | Clear all notifications                          |
| Unread Count            | GET /notifications/unread-count        | Quick unread badge count                         |
| User Search             | GET /search/users?q=                   | Search users by username                         |
| View User Profile       | GET /user/:userId                      | View another user's profile with relationship status |
| Leaderboard             | GET /leaderboard                       | Top users by rank                                |
| Suggested Users         | GET /suggested-users                   | Users with common interests sorted by rank       |
| Block User              | PATCH /block/:userId                   | Block/unblock, auto-unfollows                    |
| Comment Likes           | PATCH /comment/:commentId/like         | Like/unlike comments                             |
| Typing Indicator        | Socket typing event                    | Shows when partner is typing                     |
| Cancel Waiting          | Socket cancelWaiting                   | Leave matchmaking queue                          |
| Online/Offline Status   | Socket userOnline/userOffline          | Friends see when you connect/disconnect          |
| New Post Notification   | Auto on post creation                  | All followers get notified                       |
| Profile Bio & Avatar    | PATCH /update_profile                  | Bio and avatar fields                            |
| Paginated Feed          | GET /feed?page=1&limit=20              | Infinite scroll support                          |
