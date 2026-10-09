require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./db');
const authenticateToken = require('./authMiddleware');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_jwt_key_2026';

// Middleware configuration (10mb payload limit allows base64 avatar uploads)
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Ensure email column exists safely on existing databases
db.run("ALTER TABLE users ADD COLUMN email TEXT", () => {});

// Register Route
app.post('/api/auth/register', (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Username, email, and password are required' });
  }

  const cleanUsername = username.trim().toLowerCase();
  const cleanEmail = email.trim().toLowerCase();

  // Basic email format check
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(cleanEmail)) {
    return res.status(400).json({ error: 'Please provide a valid email address' });
  }

  const defaultAvatar = `https://ui-avatars.com/api/?name=${encodeURIComponent(cleanUsername)}&background=3b82f6&color=fff&bold=true`;
  const hashedPassword = bcrypt.hashSync(password, 10);

  db.run(
    'INSERT INTO users (username, email, password, avatar, bio) VALUES (?, ?, ?, ?, ?)',
    [cleanUsername, cleanEmail, hashedPassword, defaultAvatar, ''],
    function (err) {
      if (err) {
        if (err.message && err.message.includes('UNIQUE constraint failed')) {
          if (err.message.includes('users.email')) {
            return res.status(400).json({ error: 'Email address is already in use' });
          }
          return res.status(400).json({ error: 'Username is already taken' });
        }
        return res.status(500).json({ error: 'Database registration error: ' + err.message });
      }

      const token = jwt.sign(
        { id: this.lastID, username: cleanUsername },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.status(201).json({
        message: 'User registered successfully',
        token,
        user: { id: this.lastID, username: cleanUsername, email: cleanEmail, avatar: defaultAvatar, bio: '' }
      });
    }
  );
});

// Login Route (Supports username OR email)
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username/Email and password are required' });
  }

  const identifier = username.trim().toLowerCase();

  db.get(
    'SELECT * FROM users WHERE username = ? OR email = ?',
    [identifier, identifier],
    (err, user) => {
      if (err) return res.status(500).json({ error: 'Internal server error' });
      if (!user) return res.status(400).json({ error: 'Invalid username or password' });

      const isValid = bcrypt.compareSync(password, user.password);
      if (!isValid) return res.status(400).json({ error: 'Invalid username or password' });

      const token = jwt.sign(
        { id: user.id, username: user.username },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.json({
        message: 'Login successful',
        token,
        user: { id: user.id, username: user.username, email: user.email, avatar: user.avatar, bio: user.bio }
      });
    }
  );
});

// Current User Verification Route
app.get('/api/auth/me', authenticateToken, (req, res) => {
  db.get(
    'SELECT id, username, email, avatar, bio, created_at FROM users WHERE id = ?',
    [req.user.id],
    (err, user) => {
      if (err || !user) return res.status(404).json({ error: 'User not found' });
      res.json(user);
    }
  );
});

// Live User Search Route
app.get('/api/users/search', (req, res) => {
  const query = (req.query.q || '').trim().toLowerCase();
  if (!query) return res.json([]);

  db.all(
    'SELECT id, username, avatar, bio FROM users WHERE username LIKE ? LIMIT 8',
    [`%${query}%`],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows || []);
    }
  );
});

// Get User Profile with aggregated counts
app.get('/api/users/:username', (req, res) => {
  const targetUsername = req.params.username.toLowerCase();
  const currentUserId = req.query.currentUserId ? parseInt(req.query.currentUserId) : null;

  db.get('SELECT id, username, avatar, bio, created_at FROM users WHERE username = ?', [targetUsername], (err, profile) => {
    if (err || !profile) return res.status(404).json({ error: 'Profile not found' });

    const postCountQuery = 'SELECT COUNT(*) as count FROM posts WHERE user_id = ?';
    const followerCountQuery = 'SELECT COUNT(*) as count FROM follows WHERE following_id = ?';
    const followingCountQuery = 'SELECT COUNT(*) as count FROM follows WHERE follower_id = ?';
    const isFollowingQuery = 'SELECT COUNT(*) as count FROM follows WHERE follower_id = ? AND following_id = ?';

    db.get(postCountQuery, [profile.id], (err, pCount) => {
      db.get(followerCountQuery, [profile.id], (err, folCount) => {
        db.get(followingCountQuery, [profile.id], (err, fingCount) => {
          db.get(isFollowingQuery, [currentUserId || 0, profile.id], (err, isFol) => {
            res.json({
              ...profile,
              postCount: pCount ? pCount.count : 0,
              followerCount: folCount ? folCount.count : 0,
              followingCount: fingCount ? fingCount.count : 0,
              isFollowing: isFol ? isFol.count > 0 : false
            });
          });
        });
      });
    });
  });
});

// Update Profile Bio and Avatar
app.put('/api/users/profile', authenticateToken, (req, res) => {
  const { bio, avatar } = req.body;
  const updates = [];
  const params = [];

  if (typeof bio === 'string') {
    updates.push('bio = ?');
    params.push(bio.trim());
  }

  if (typeof avatar === 'string' && avatar.trim()) {
    updates.push('avatar = ?');
    params.push(avatar.trim());
  }

  if (updates.length === 0) {
    return res.status(400).json({ error: 'No fields provided for update' });
  }

  params.push(req.user.id);
  const sql = `UPDATE users SET ${updates.join(', ')} WHERE id = ?`;

  db.run(sql, params, function (err) {
    if (err) return res.status(500).json({ error: 'Failed to update profile' });
    db.get('SELECT id, username, avatar, bio FROM users WHERE id = ?', [req.user.id], (err, updatedUser) => {
      res.json({ message: 'Profile updated successfully', user: updatedUser });
    });
  });
});

// Followers List
app.get('/api/users/:username/followers', (req, res) => {
  const sql = `
    SELECT u.id, u.username, u.avatar, u.bio
    FROM follows f
    JOIN users u ON f.follower_id = u.id
    WHERE f.following_id = (SELECT id FROM users WHERE username = ?)
    ORDER BY f.created_at DESC
  `;
  db.all(sql, [req.params.username.toLowerCase()], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows || []);
  });
});

// Following List
app.get('/api/users/:username/following', (req, res) => {
  const sql = `
    SELECT u.id, u.username, u.avatar, u.bio
    FROM follows f
    JOIN users u ON f.following_id = u.id
    WHERE f.follower_id = (SELECT id FROM users WHERE username = ?)
    ORDER BY f.created_at DESC
  `;
  db.all(sql, [req.params.username.toLowerCase()], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows || []);
  });
});

// Fetch News Feed
app.get('/api/posts', (req, res) => {
  const currentUserId = req.query.userId || req.query.currentUserId || 0;
  const targetUsername = req.query.username || null;
  const feedType = req.query.feed || 'global';

  let filterClause = '';
  let params = [currentUserId, currentUserId];

  if (targetUsername) {
    filterClause = 'WHERE u.username = ?';
    params.push(targetUsername.toLowerCase());
  } else if (feedType === 'following' && currentUserId) {
    filterClause = 'WHERE p.user_id IN (SELECT following_id FROM follows WHERE follower_id = ?)';
    params.push(currentUserId);
  }

  const query = `
    SELECT 
      p.id, 
      p.content, 
      p.created_at, 
      p.user_id,
      u.username, 
      u.avatar,
      (SELECT COUNT(*) FROM likes WHERE post_id = p.id) AS likes_count,
      (SELECT COUNT(*) FROM comments WHERE post_id = p.id) AS comments_count,
      CASE 
        WHEN ? IS NOT NULL AND ? > 0 THEN (SELECT 1 FROM likes WHERE post_id = p.id AND user_id = ?)
        ELSE 0 
      END AS is_liked
    FROM posts p
    JOIN users u ON p.user_id = u.id
    ${filterClause}
    ORDER BY p.created_at DESC
  `;

  // Provide third parameter for the is_liked query clause
  params.splice(2, 0, currentUserId);

  db.all(query, params, (err, posts) => {
    if (err) {
      console.error('Error fetching posts:', err.message);
      return res.status(500).json({ error: 'Failed to retrieve posts' });
    }

    if (!posts || posts.length === 0) {
      return res.json([]);
    }

    const postIds = posts.map(p => p.id);
    const placeholders = postIds.map(() => '?').join(',');

    const commentQuery = `
      SELECT c.*, u.username, u.avatar 
      FROM comments c
      JOIN users u ON c.user_id = u.id
      WHERE c.post_id IN (${placeholders})
      ORDER BY c.created_at ASC
    `;

    db.all(commentQuery, postIds, (commentErr, allComments) => {
      const commentMap = {};
      if (!commentErr && allComments) {
        allComments.forEach(c => {
          if (!commentMap[c.post_id]) commentMap[c.post_id] = [];
          commentMap[c.post_id].push(c);
        });
      }

      const fullPosts = posts.map(p => {
        const totalLikes = p.likes_count ?? 0;
        const postComments = commentMap[p.id] || [];
        const totalComments = p.comments_count ?? postComments.length;

        return {
          ...p,
          likes_count: totalLikes,
          like_count: totalLikes,
          comments_count: totalComments,
          comment_count: totalComments,
          is_liked: Boolean(p.is_liked),
          user_liked: Boolean(p.is_liked),
          comments: postComments
        };
      });

      res.json(fullPosts);
    });
  });
});

// Create Post
app.post('/api/posts', authenticateToken, (req, res) => {
  const { content } = req.body;
  if (!content || !content.trim()) {
    return res.status(400).json({ error: 'Post content cannot be empty' });
  }

  db.run(
    'INSERT INTO posts (user_id, content) VALUES (?, ?)',
    [req.user.id, content.trim()],
    function (err) {
      if (err) return res.status(500).json({ error: 'Failed to publish post' });
      res.status(201).json({ message: 'Post published successfully', id: this.lastID });
    }
  );
});

// Delete Post
app.delete('/api/posts/:id', authenticateToken, (req, res) => {
  db.run(
    'DELETE FROM posts WHERE id = ? AND user_id = ?',
    [req.params.id, req.user.id],
    function (err) {
      if (err) return res.status(500).json({ error: 'Failed to delete post' });
      if (this.changes === 0) {
        return res.status(403).json({ error: 'Unauthorized or post does not exist' });
      }
      res.json({ message: 'Post removed successfully' });
    }
  );
});

// Add Comment (Robust and fully error-logged)
app.post('/api/posts/:id/comments', authenticateToken, (req, res) => {
  const content = req.body && req.body.content ? req.body.content.trim() : '';
  const postId = parseInt(req.params.id, 10);
  const userId = req.user && req.user.id ? parseInt(req.user.id, 10) : null;

  if (!postId || isNaN(postId)) {
    return res.status(400).json({ error: 'Invalid post ID' });
  }

  if (!userId) {
    return res.status(401).json({ error: 'Invalid user session. Please log in again.' });
  }

  if (!content) {
    return res.status(400).json({ error: 'Comment text cannot be empty' });
  }

  // Ensure table exists without restrictive constraints that break on existing databases
  db.run(`
    CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      post_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `, (tableErr) => {
    if (tableErr) {
      console.error('Comments table check failed:', tableErr.message);
      return res.status(500).json({ error: 'Database table error: ' + tableErr.message });
    }

    db.run(
      'INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)',
      [postId, userId, content],
      function (insertErr) {
        if (insertErr) {
          console.error('CRITICAL: Comment insertion failed:', insertErr.message);
          return res.status(500).json({ error: 'DB Error: ' + insertErr.message });
        }

        console.log(`Comment #${this.lastID} added to post #${postId} by user #${userId}`);

        // Return direct payload
        res.status(201).json({
          id: this.lastID,
          post_id: postId,
          user_id: userId,
          content: content,
          created_at: new Date().toISOString(),
          username: req.user.username,
          avatar: req.user.avatar || `https://ui-avatars.com/api/?name=${encodeURIComponent(req.user.username)}&background=3b82f6&color=fff&bold=true`
        });
      }
    );
  });
});

// Toggle Like
app.post('/api/posts/:id/like', authenticateToken, (req, res) => {
  const postId = req.params.id;
  const userId = req.user.id;

  db.get('SELECT * FROM likes WHERE user_id = ? AND post_id = ?', [userId, postId], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database check failed' });

    if (row) {
      db.run('DELETE FROM likes WHERE user_id = ? AND post_id = ?', [userId, postId], (delErr) => {
        if (delErr) return res.status(500).json({ error: 'Failed to unlike post' });
        res.json({ liked: false });
      });
    } else {
      db.run('INSERT INTO likes (user_id, post_id) VALUES (?, ?)', [userId, postId], (insErr) => {
        if (insErr) return res.status(500).json({ error: 'Failed to like post' });
        res.json({ liked: true });
      });
    }
  });
});

// Follow / Unfollow User Toggle
app.post('/api/users/:username/follow', authenticateToken, (req, res) => {
  const targetUsername = req.params.username.toLowerCase();

  db.get('SELECT id FROM users WHERE username = ?', [targetUsername], (err, targetUser) => {
    if (err || !targetUser) return res.status(404).json({ error: 'Target user not found' });
    if (targetUser.id === req.user.id) {
      return res.status(400).json({ error: 'You cannot follow yourself' });
    }

    db.get(
      'SELECT * FROM follows WHERE follower_id = ? AND following_id = ?',
      [req.user.id, targetUser.id],
      (fErr, followRow) => {
        if (fErr) return res.status(500).json({ error: 'Database check failed' });

        if (followRow) {
          db.run(
            'DELETE FROM follows WHERE follower_id = ? AND following_id = ?',
            [req.user.id, targetUser.id],
            (delErr) => {
              if (delErr) return res.status(500).json({ error: 'Failed to unfollow user' });
              res.json({ following: false });
            }
          );
        } else {
          db.run(
            'INSERT INTO follows (follower_id, following_id) VALUES (?, ?)',
            [req.user.id, targetUser.id],
            (insErr) => {
              if (insErr) return res.status(500).json({ error: 'Failed to follow user' });
              res.json({ following: true });
            }
          );
        }
      }
    );
  });
});

// SPA Catch-All Handler (Express 5 compatible wildcard)
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Server
app.listen(PORT, () => {
  console.log(`🚀 Mini Social Media Server running at http://localhost:${PORT}`);
});