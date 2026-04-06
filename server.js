const express = require('express');
const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production-set-JWT_SECRET-env-var';

// Wait for DB file to be ready
let db;
let dbReady = false;

function getDb() {
  if (!dbReady || !db) throw new Error('Database not ready');
  return db;
}

function initDb() {
  try {
    const dbPath = process.env.DB_PATH || path.join(__dirname, 'data', 'picks.json');
    const adapter = new FileSync(dbPath);
    db = low(adapter);
    
    db.defaults({
      users: [],
      golf_tournaments: [],
      golf_picks: [],
      soccer_weeks: [],
      soccer_games: [],
      soccer_picks: [],
      settings: {}
    }).write();
    
    dbReady = true;
    console.log('Database ready');
  } catch (e) {
    console.log('DB init failed, retrying...:', e.message);
    setTimeout(initDb, 1000);
  }
}

initDb();

function nextId(collection) {
  const items = db.get(collection).value();
  return items.length === 0 ? 1 : Math.max(...items.map(i => i.id)) + 1;
}

function now() { return new Date().toISOString(); }

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function adminOnly(req, res, next) {
  if (!req.user?.is_admin) return res.status(403).json({ error: 'Admin access required' });
  next();
}

function superAdminOnly(req, res, next) {
  if (!req.user?.is_super_admin) return res.status(403).json({ error: 'Super admin access required' });
  next();
}

// ─── Auth ─────────────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body || {};
    if (!username?.trim() || !email?.trim() || !password)
      return res.status(400).json({ error: 'Username, email and password are required' });
    if (password.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const users = db.get('users').value();
    if (users.some(u => u.username.toLowerCase() === username.trim().toLowerCase()))
      return res.status(409).json({ error: 'Username already taken' });
    if (users.some(u => u.email.toLowerCase() === email.trim().toLowerCase()))
      return res.status(409).json({ error: 'Email already in use' });

    const isFirstUser = users.length === 0;
    const hash = await bcrypt.hash(password, 10);
    const user = {
      id: nextId('users'),
      username: username.trim(),
      email: email.trim().toLowerCase(),
      password_hash: hash,
      is_admin: isFirstUser,
      is_super_admin: isFirstUser,
      created_at: now()
    };

    db.get('users').push(user).write();

    const token = jwt.sign({ id: user.id, username: user.username, is_admin: user.is_admin, is_super_admin: user.is_super_admin }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user.id, username: user.username, email: user.email, is_admin: user.is_admin, is_super_admin: user.is_super_admin } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const user = db.get('users').find(u => u.username.toLowerCase() === (username || '').toLowerCase()).value();
    if (!user || !(await bcrypt.compare(password, user.password_hash)))
      return res.status(401).json({ error: 'Invalid username or password' });

    const token = jwt.sign({ id: user.id, username: user.username, is_admin: user.is_admin, is_super_admin: user.is_super_admin }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user.id, username: user.username, email: user.email, is_admin: user.is_admin, is_super_admin: user.is_super_admin || false } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// ─── User Management ──────────────────────────────────────────────────────────
app.get('/api/users', auth, adminOnly, (req, res) => {
  const users = db.get('users').map(u => ({
    id: u.id, username: u.username, email: u.email, is_admin: u.is_admin, is_kennure: u.is_kennure || false, created_at: u.created_at
  })).sortBy('username').value();
  res.json(users);
});

app.put('/api/users/:id/admin', auth, adminOnly, (req, res) => {
  const targetId = parseInt(req.params.id);
  if (targetId === req.user.id) return res.status(400).json({ error: 'You cannot change your own admin status' });
  const user = db.get('users').find({ id: targetId }).value();
  if (!user) return res.status(404).json({ error: 'User not found' });
  db.get('users').find({ id: targetId }).assign({ is_admin: Boolean(req.body.is_admin) }).write();
  res.json({ success: true });
});

app.put('/api/users/:id/kennure', auth, adminOnly, (req, res) => {
  const targetId = parseInt(req.params.id);
  const user = db.get('users').find({ id: targetId }).value();
  if (!user) return res.status(404).json({ error: 'User not found' });
  db.get('users').find({ id: targetId }).assign({ is_kennure: Boolean(req.body.is_kennure) }).write();
  res.json({ success: true });
});

app.put('/api/users/:id', auth, (req, res) => {
  const targetId = parseInt(req.params.id);
  if (targetId !== req.user.id) return res.status(403).json({ error: 'Not authorized' });
  const { username } = req.body || {};
  if (!username?.trim()) return res.status(400).json({ error: 'Username required' });
  db.get('users').find({ id: targetId }).assign({ username: username.trim() }).write();
  res.json({ success: true });
});

app.put('/api/users/:id/password', auth, (req, res) => {
  const targetId = parseInt(req.params.id);
  if (targetId !== req.user.id) return res.status(403).json({ error: 'Not authorized' });
  const { password } = req.body || {};
  if (!password || password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const hashed = bcrypt.hashSync(password, 10);
  db.get('users').find({ id: targetId }).assign({ password: hashed }).write();
  res.json({ success: true });
});

app.delete('/api/users/:id', auth, (req, res) => {
  const targetId = parseInt(req.params.id);
  if (targetId !== req.user.id) return res.status(403).json({ error: 'Not authorized' });
  db.get('golf_picks').remove({ user_id: targetId }).write();
  db.get('soccer_picks').remove({ user_id: targetId }).write();
  db.get('users').remove({ id: targetId }).write();
  res.json({ success: true });
});

// ─── Golf Tournaments ─────────────────────────────────────────────────────────
app.get('/api/golf/tournaments', (req, res) => {
  try {
    const tournaments = db.get('golf_tournaments').orderBy('created_at', 'desc').value();
    const myPicks = req.user ? db.get('golf_picks').filter({ user_id: req.user.id }).value() : [];
    const pickMap = Object.fromEntries(myPicks.map(p => [p.tournament_id, p]));

    res.json(tournaments.map(t => ({
      ...t,
      my_pick: pickMap[t.id] ? {
        picked_golfer: pickMap[t.id].picked_golfer,
        result_category: pickMap[t.id].result_category,
        points_earned: pickMap[t.id].points_earned,
        created_at: pickMap[t.id].created_at
      } : null
    })));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/golf/tournaments', auth, adminOnly, (req, res) => {
  const { name, course, start_date, deadline, predicted_top5, event_type, field } = req.body || {};
  if (!name?.trim()) return res.status(400).json({ error: 'Tournament name required' });
  if (!['regular','signature','major'].includes(event_type))
    return res.status(400).json({ error: 'Event type must be regular, signature, or major' });

  const tournament = {
    id: nextId('golf_tournaments'),
    name: name.trim(),
    course: course?.trim() || null,
    start_date: start_date || null,
    deadline: deadline || null,
    predicted_top5: (predicted_top5 || []).filter(g => g?.trim()),
    field: (field || []).map(f => f.trim()).filter(f => f),
    event_type: event_type || 'regular',
    results_entered: false,
    created_at: now()
  };

  db.get('golf_tournaments').push(tournament).write();
  res.json({ id: tournament.id });
});

app.put('/api/golf/tournaments/:id', auth, adminOnly, (req, res) => {
  const id = parseInt(req.params.id);
  const { name, course, event_type, start_date, deadline, field } = req.body || {};
  if (name !== undefined) db.get('golf_tournaments').find({ id }).assign({ name: name.trim() }).write();
  if (course !== undefined) db.get('golf_tournaments').find({ id }).assign({ course: course?.trim() || null }).write();
  if (event_type !== undefined && ['regular','signature','major'].includes(event_type)) 
    db.get('golf_tournaments').find({ id }).assign({ event_type }).write();
  if (start_date !== undefined) db.get('golf_tournaments').find({ id }).assign({ start_date: start_date || null }).write();
  if (deadline !== undefined) db.get('golf_tournaments').find({ id }).assign({ deadline: deadline || null }).write();
  if (field !== undefined) db.get('golf_tournaments').find({ id }).assign({ field: (field || []).map(f => f.trim()).filter(f => f) }).write();
  res.json({ success: true });
});

app.delete('/api/golf/tournaments/:id', auth, adminOnly, (req, res) => {
  const id = parseInt(req.params.id);
  db.get('golf_picks').remove({ tournament_id: id }).write();
  db.get('golf_tournaments').remove({ id }).write();
  res.json({ success: true });
});

app.delete('/api/golf/tournaments', auth, superAdminOnly, (req, res) => {
  const completed = db.get('golf_tournaments').filter(t => t.results_entered).value();
  completed.forEach(t => {
    db.get('golf_picks').remove({ tournament_id: t.id }).write();
    db.get('golf_tournaments').remove({ id: t.id }).write();
  });
  res.json({ success: true, deleted: completed.length });
});

app.get('/api/golf/tournaments/:id/picks', (req, res) => {
  const tournamentId = parseInt(req.params.id);
  const tournament = db.get('golf_tournaments').find({ id: tournamentId }).value();
  const picks = db.get('golf_picks').filter({ tournament_id: tournamentId }).value();
  const users = db.get('users').value();

  const deadlinePassed = tournament && (tournament.results_entered || (tournament.deadline && new Date() >= new Date(tournament.deadline)));

  // If deadline hasn't passed and user not authenticated, hide picks
  const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
  if (!deadlinePassed && !token) {
    return res.json([]);
  }

  // Verify user if token provided
  if (token) {
    try {
      req.user = jwt.verify(token, JWT_SECRET);
    } catch {}
  }

  // Admins can always see all picks
  if (req.user?.is_admin) {
    const userMap = Object.fromEntries(users.map(u => [u.id, { username: u.username, is_kennure: u.is_kennure }]));
    return res.json(picks.map(p => ({ ...p, username: userMap[p.user_id]?.username || 'Unknown', is_kennure: userMap[p.user_id]?.is_kennure || false })));
  }

  // If deadline passed, show all picks
  if (deadlinePassed) {
    const userMap = Object.fromEntries(users.map(u => [u.id, { username: u.username }]));
    return res.json(picks.map(p => ({ ...p, username: userMap[p.user_id]?.username || 'Unknown' })));
  }

  // Otherwise just show own picks
  if (req.user) {
    const myPicks = picks.filter(p => p.user_id === req.user.id);
    const user = users.find(u => u.id === req.user.id);
    return res.json(myPicks.map(p => ({ id: p.id, picked_golfer: p.picked_golfer, result_category: p.result_category, points_earned: p.points_earned, username: user?.username })));
  }

  res.json([]);
});

app.post('/api/golf/tournaments/:id/pick', auth, (req, res) => {
  const { picked_golfer } = req.body || {};
  if (!picked_golfer?.trim()) return res.status(400).json({ error: 'Golfer name required' });
  if (!req.user || !req.user.id) return res.status(401).json({ error: 'Not authenticated' });

  const tournamentId = parseInt(req.params.id);
  const tournament = db.get('golf_tournaments').find({ id: tournamentId }).value();
  if (!tournament) return res.status(404).json({ error: 'Tournament not found' });
  if (tournament.results_entered) return res.status(400).json({ error: 'Results already entered — picks are locked' });
  if (tournament.deadline && new Date() >= new Date(tournament.deadline)) return res.status(400).json({ error: 'Picks have been closed for this tournament' });

  const existingPicks = db.get('golf_picks').filter({ tournament_id: tournamentId, user_id: req.user.id }).value();
  if (existingPicks && existingPicks.length > 0) return res.status(400).json({ error: 'You already have a pick locked in for this tournament' });

  const top5 = tournament.predicted_top5 || [];
  if (top5.length > 0 && top5.some(g => g.toLowerCase() === picked_golfer.trim().toLowerCase()))
    return res.status(400).json({ error: `${picked_golfer.trim()} is in the predicted Top 5 — you must pick someone else!` });

  db.get('golf_picks').push({
      id: nextId('golf_picks'),
      tournament_id: tournamentId,
      user_id: req.user.id,
      picked_golfer: picked_golfer.trim(),
      result_category: null,
      points_earned: 0,
      created_at: now()
    }).write();

  res.json({ success: true });
});

app.delete('/api/golf/picks/:pickId', auth, adminOnly, (req, res) => {
  const pickId = parseInt(req.params.pickId);
  db.get('golf_picks').remove({ id: pickId }).write();
  res.json({ success: true });
});

app.put('/api/golf/tournaments/:id/results', auth, adminOnly, (req, res) => {
  const { results } = req.body || {};
  const pointsMap = { winner: 15, top5: 10, top10: 8, top20: 4, made_cut: 1, other: 0 };
  const tournament = db.get('golf_tournaments').find({ id: parseInt(req.params.id) }).value();
  const multiplier = tournament?.event_type === 'major' ? 1.5 : tournament?.event_type === 'signature' ? 1.25 : 1;

  for (const [pickId, category] of Object.entries(results)) {
    const basePoints = pointsMap[category] ?? 0;
    const points = Math.round(basePoints * multiplier * 10) / 10;
    db.get('golf_picks').find({ id: parseInt(pickId) }).assign({ result_category: category, points_earned: points }).write();
  }
  db.get('golf_tournaments').find({ id: parseInt(req.params.id) }).assign({ results_entered: true }).write();

  res.json({ success: true });
});

app.put('/api/golf/tournaments/:id/top5', auth, adminOnly, (req, res) => {
  const { predicted_top5 } = req.body || {};
  if (!Array.isArray(predicted_top5)) return res.status(400).json({ error: 'predicted_top5 must be an array' });
  db.get('golf_tournaments').find({ id: parseInt(req.params.id) }).assign({ predicted_top5 }).write();
  res.json({ success: true });
});

app.get('/api/golf/leaderboard', (req, res) => {
  try {
    const users = db.get('users').value();
    const allPicks = db.get('golf_picks').value();

    const leaderboard = users.map(u => {
      const picks = allPicks.filter(p => p.user_id === u.id);
      return {
        id: u.id,
        username: u.username,
        is_kennure: u.is_kennure || false,
        total_points: picks.reduce((s, p) => s + (p.points_earned || 0), 0),
        total_picks: picks.length,
        wins:   picks.filter(p => p.result_category === 'winner').length,
        top5s:  picks.filter(p => ['winner','top5'].includes(p.result_category)).length,
        top10s: picks.filter(p => ['winner','top5','top10'].includes(p.result_category)).length,
        results_recorded: picks.filter(p => p.result_category).length
      };
    }).sort((a, b) => b.total_points - a.total_points || b.wins - a.wins || b.top5s - a.top5s);

    res.json(leaderboard);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Soccer Weeks ─────────────────────────────────────────────────────────────
app.get('/api/soccer/weeks', (req, res) => {
  try {
    const weeks = db.get('soccer_weeks').orderBy('created_at', 'desc').value();
    const allGames = db.get('soccer_games').value();
    const myPicks = req.user ? db.get('soccer_picks').filter({ user_id: req.user.id }).value() : [];
    const picksByGame = Object.fromEntries(myPicks.map(p => [p.game_id, p]));

    res.json(weeks.map(w => ({
      ...w,
      games: allGames
        .filter(g => g.week_id === w.id)
        .sort((a, b) => a.game_order - b.game_order)
        .map(g => ({ ...g, my_pick: picksByGame[g.id] || null }))
    })));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/soccer/weeks', auth, superAdminOnly, (req, res) => {
  const { week_name, deadline, games } = req.body || {};
  if (!week_name?.trim()) return res.status(400).json({ error: 'Week name required' });
  if (!Array.isArray(games) || games.length !== 3) return res.status(400).json({ error: 'Exactly 3 games required' });
  if (games.some(g => !g.home_team?.trim() || !g.away_team?.trim()))
    return res.status(400).json({ error: 'Each game needs a home and away team' });

  const week = { id: nextId('soccer_weeks'), week_name: week_name.trim(), deadline: deadline || null, results_entered: false, created_at: now() };
  db.get('soccer_weeks').push(week).write();

  games.forEach((g, i) => {
    db.get('soccer_games').push({
      id: nextId('soccer_games'),
      week_id: week.id,
      home_team: g.home_team.trim(),
      away_team: g.away_team.trim(),
      actual_home_score: null,
      actual_away_score: null,
      game_order: i + 1
    }).write();
  });

  res.json({ id: week.id });
});

app.put('/api/soccer/weeks/:id', auth, superAdminOnly, (req, res) => {
  const id = parseInt(req.params.id);
  const { week_name, deadline } = req.body || {};
  if (week_name !== undefined) db.get('soccer_weeks').find({ id }).assign({ week_name: week_name.trim() }).write();
  if (deadline !== undefined) db.get('soccer_weeks').find({ id }).assign({ deadline: deadline || null }).write();
  res.json({ success: true });
});

app.delete('/api/soccer/weeks/:id', auth, superAdminOnly, (req, res) => {
  const weekId = parseInt(req.params.id);
  const games = db.get('soccer_games').filter({ week_id: weekId }).value();
  games.forEach(g => db.get('soccer_picks').remove({ game_id: g.id }).write());
  db.get('soccer_games').remove({ week_id: weekId }).write();
  db.get('soccer_weeks').remove({ id: weekId }).write();
  res.json({ success: true });
});

app.delete('/api/soccer/weeks', auth, superAdminOnly, (req, res) => {
  const completed = db.get('soccer_weeks').filter(w => w.results_entered).value();
  completed.forEach(w => {
    const games = db.get('soccer_games').filter({ week_id: w.id }).value();
    games.forEach(g => db.get('soccer_picks').remove({ game_id: g.id }).write());
    db.get('soccer_games').remove({ week_id: w.id }).write();
    db.get('soccer_weeks').remove({ id: w.id }).write();
  });
  res.json({ success: true, deleted: completed.length });
});

app.get('/api/soccer/weeks/:id/picks', auth, (req, res) => {
  const weekId = parseInt(req.params.id);
  const week = db.get('soccer_weeks').find({ id: weekId }).value();
  const games = db.get('soccer_games').filter({ week_id: weekId }).value();
  const gameIds = games.map(g => g.id);

  // Hide other users' picks until deadline or results entered
  const deadlinePassed = week && (week.results_entered || (week.deadline && new Date() >= new Date(week.deadline)));
  if (!deadlinePassed) {
    const myPicks = db.get('soccer_picks').filter(p => gameIds.includes(p.game_id) && p.user_id === req.user.id).value();
    const users = db.get('users').value();
    const user = users.find(u => u.id === req.user.id);
    return res.json(myPicks.map(p => {
      const game = games.find(g => g.id === p.game_id);
      return { ...p, username: user?.username, home_team: game?.home_team, away_team: game?.away_team, actual_home_score: game?.actual_home_score, actual_away_score: game?.actual_away_score, game_order: game?.game_order };
    }));
  }

  const picks = db.get('soccer_picks').filter(p => gameIds.includes(p.game_id)).value();
  const users = db.get('users').value();

  const result = picks.map(p => {
    const user = users.find(u => u.id === p.user_id);
    const game = games.find(g => g.id === p.game_id);
    return { ...p, username: user?.username, home_team: game?.home_team, away_team: game?.away_team, actual_home_score: game?.actual_home_score, actual_away_score: game?.actual_away_score, game_order: game?.game_order };
  }).sort((a, b) => (a.username || '').localeCompare(b.username || '') || a.game_order - b.game_order);

  res.json(result);
});

app.post('/api/soccer/weeks/:id/picks', auth, (req, res) => {
  const { picks } = req.body || {};
  const weekId = parseInt(req.params.id);
  const week = db.get('soccer_weeks').find({ id: weekId }).value();
  if (!week) return res.status(404).json({ error: 'Week not found' });
  if (week.results_entered) return res.status(400).json({ error: 'Results already entered — picks are locked' });
  if (week.deadline) {
    const dl = new Date(week.deadline);
    if (new Date() >= dl) return res.status(400).json({ error: 'Deadline has passed — picks are locked' });
  }
  if (!Array.isArray(picks) || picks.length !== 3) return res.status(400).json({ error: 'All 3 picks required' });
  if (picks.some(p => !Number.isInteger(p.predicted_home) || !Number.isInteger(p.predicted_away) || p.predicted_home < 0 || p.predicted_away < 0))
    return res.status(400).json({ error: 'Invalid scores — must be non-negative numbers' });

  picks.forEach(p => {
    const existing = db.get('soccer_picks').find({ game_id: p.game_id, user_id: req.user.id }).value();
    if (existing) {
      db.get('soccer_picks').find({ id: existing.id }).assign({ predicted_home: p.predicted_home, predicted_away: p.predicted_away, points_earned: 0 }).write();
    } else {
      db.get('soccer_picks').push({
        id: nextId('soccer_picks'),
        game_id: p.game_id,
        user_id: req.user.id,
        predicted_home: p.predicted_home,
        predicted_away: p.predicted_away,
        points_earned: 0,
        created_at: now()
      }).write();
    }
  });

  res.json({ success: true });
});

app.put('/api/soccer/weeks/:id/results', auth, superAdminOnly, (req, res) => {
  const { game_results } = req.body || {};
  const outcome = (h, a) => h > a ? 'H' : a > h ? 'A' : 'D';

  for (const r of game_results) {
    db.get('soccer_games').find({ id: r.game_id }).assign({ actual_home_score: r.home_score, actual_away_score: r.away_score }).write();
    const actual = outcome(r.home_score, r.away_score);
    const picks = db.get('soccer_picks').filter({ game_id: r.game_id }).value();
    picks.forEach(pick => {
      let pts = 0;
      if (pick.predicted_home === r.home_score && pick.predicted_away === r.away_score) {
        pts = 3;
      } else if (outcome(pick.predicted_home, pick.predicted_away) === actual) {
        pts = 1;
      }
      db.get('soccer_picks').find({ id: pick.id }).assign({ points_earned: pts }).write();
    });
  }

  db.get('soccer_weeks').find({ id: parseInt(req.params.id) }).assign({ results_entered: true }).write();
  res.json({ success: true });
});

app.get('/api/soccer/leaderboard', (req, res) => {
  try {
    const users = db.get('users').filter(u => u.is_admin).value();
    const allPicks = db.get('soccer_picks').value();

    const leaderboard = users.map(u => {
      const picks = allPicks.filter(p => p.user_id === u.id);
      return {
        id: u.id,
        username: u.username,
        total_points: picks.reduce((s, p) => s + (p.points_earned || 0), 0),
        exact_scores: picks.filter(p => p.points_earned === 3).length,
        correct_results: picks.filter(p => p.points_earned === 1).length,
        total_picks: picks.length
      };
    }).sort((a, b) => b.total_points - a.total_points || b.exact_scores - a.exact_scores);

    res.json(leaderboard);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/soccer/leaderboard/:userId', auth, superAdminOnly, (req, res) => {
  const userId = parseInt(req.params.userId);
  const { adjustment } = req.body || {};
  if (!Number.isInteger(adjustment)) return res.status(400).json({ error: 'Adjustment must be an integer' });
  const user = db.get('users').find({ id: userId }).value();
  if (!user) return res.status(404).json({ error: 'User not found' });
  const picks = db.get('soccer_picks').filter({ user_id: userId }).value();
  if (!picks.length && adjustment !== 0) {
    db.get('soccer_picks').push({ id: nextId('soccer_picks'), game_id: 0, user_id: userId, predicted_home: 0, predicted_away: 0, points_earned: adjustment, created_at: now() }).write();
  } else if (picks.length) {
    const totalPts = picks.reduce((s, p) => s + (p.points_earned || 0), 0);
    const lastPick = picks[picks.length - 1];
    const newLast = (lastPick.points_earned || 0) + adjustment;
    db.get('soccer_picks').find({ id: lastPick.id }).assign({ points_earned: Math.max(0, newLast) }).write();
  }
  res.json({ success: true });
});

// ─── ESPN Live Sync ───────────────────────────────────────────────────────────
app.post('/api/golf/tournaments/:id/sync-espn', auth, adminOnly, async (req, res) => {
  const tournamentId = parseInt(req.params.id);
  const tournament = db.get('golf_tournaments').find({ id: tournamentId }).value();
  if (!tournament) return res.status(404).json({ error: 'Tournament not found' });

  try {
    const response = await fetch('https://site.api.espn.com/apis/site/v2/sports/golf/pga/scoreboard');
    if (!response.ok) throw new Error('ESPN API returned ' + response.status);
    const data = await response.json();

    const event = data.events?.[0];
    if (!event) return res.status(404).json({ error: 'No active PGA tournament found on ESPN right now' });

    const competitors = event.competitions?.[0]?.competitors || [];
    console.log(`[SYNC] Event: ${event.name}, Competitors: ${competitors.length}, tournament.event_type: ${tournament.event_type}`);
    
    // Debug: log all competitor names
    const competitorNames = competitors.map(c => c.athlete?.displayName || 'unknown');
    console.log(`[SYNC] All competitors:`, competitorNames.slice(0, 20).join(', '), '...');
    
    const picks = db.get('golf_picks').filter({ tournament_id: tournamentId }).value();

    // First pass: collect all scores
    const pickData = [];
    for (const pick of picks) {
      const search = pick.picked_golfer.toLowerCase();
      const lastName = search.split(' ').pop();

      const match = competitors.find(c => {
        const dn = (c.athlete?.displayName || '').toLowerCase().replace(/\s+/g, ' ').trim();
        const sn = (c.athlete?.shortName || '').toLowerCase().replace(/\s+/g, ' ').trim();
        const searchNorm = search.replace(/\s+/g, ' ').trim();
        const searchParts = searchNorm.split(' ');
        
        // If search is initials like "S w kim", try to match first name initial + last name
        if (searchParts.length >= 2 && searchParts[0].length <= 2 && searchParts[1].length <= 2) {
          const lastName = searchParts[searchParts.length - 1];
          const firstInitial = searchParts[0].charAt(0);
          // Match if last name matches AND first name starts with that initial
          if (dn.endsWith(lastName) && dn.startsWith(firstInitial)) {
            return true;
          }
        }
        
        const searchLast = searchNorm.split(' ').pop();
        
        // Try various matching strategies
        return dn === searchNorm 
            || dn.includes(searchNorm) 
            || searchNorm.includes(dn)
            || (searchNorm.split(' ').length > 1 && dn.endsWith(searchLast))
            || (sn && sn.endsWith(searchLast));
      });

      if (match) {
        const linescores = match.linescores || [];
        const athleteName = match.athlete?.displayName || 'Unknown';
        
        console.log(`[SYNC] MATCH: "${pick.picked_golfer}" matched to "${athleteName}"`);
        
        let totalToPar = 0;
        let roundsCompleted = 0;
        
        for (const round of linescores) {
          const toPar = parseInt(round.displayValue);
          if (!isNaN(toPar)) {
            totalToPar += toPar;
            roundsCompleted++;
          }
        }
        
        pickData.push({ pick, totalToPar, roundsCompleted });
        console.log(`[SYNC] ${pick.picked_golfer}: toPar=${totalToPar}, rounds=${roundsCompleted}`);
      } else {
        console.log(`[SYNC] NOT FOUND: ${pick.picked_golfer}`);
        notFound.push(pick.picked_golfer);
      }
    }
    
    // Sort by totalToPar (lowest = best) to determine positions
    // For ties, use more rounds completed as tiebreaker
    pickData.sort((a, b) => {
      if (a.totalToPar !== b.totalToPar) return a.totalToPar - b.totalToPar;
      return b.roundsCompleted - a.roundsCompleted;
    });

    const pointsMap = { winner: 15, top5: 10, top10: 8, top20: 4, made_cut: 1, other: 0 };
    const multiplier = tournament.event_type === 'major' ? 1.5
                     : tournament.event_type === 'signature' ? 1.25 : 1;
    const updated = [], notFound = [], results = [];

    // Second pass: assign categories based on rounds completed and position
    // Players with 4 rounds made the cut
    // Players with < 4 rounds missed the cut or withdrew
    for (let i = 0; i < pickData.length; i++) {
      const { pick, totalToPar, roundsCompleted } = pickData[i];
      
      let category;
      if (roundsCompleted < 4) {
        // Missed cut or withdrew - 0 points
        category = 'other';
      } else {
        // Made the cut - rank among all players who made cut
        const pos = i + 1;
        if (pos === 1) category = 'winner';
        else if (pos <= 5) category = 'top5';
        else if (pos <= 10) category = 'top10';
        else if (pos <= 20) category = 'top20';
        else category = 'made_cut';
      }

      const points = Math.round((pointsMap[category] ?? 0) * multiplier * 10) / 10;
      console.log(`[SYNC] ${pick.picked_golfer}: position=${i+1}, toPar=${totalToPar}, rounds=${roundsCompleted}, category=${category}, points=${points}`);
      
      db.get('golf_picks').find({ id: pick.id })
        .assign({ result_category: category, points_earned: points }).write();

      updated.push(pick.picked_golfer);
      results.push({ golfer: pick.picked_golfer, position: i+1, toPar: totalToPar, rounds: roundsCompleted, category, points });
    }

    // Stamp tournament with sync metadata (does NOT lock it)
    db.get('golf_tournaments').find({ id: tournamentId }).assign({
      last_espn_sync: now(),
      espn_event_name: event.name,
      espn_round: event.competitions?.[0]?.status?.type?.shortDetail || null
    }).write();

    // If finalize flag is set, lock the tournament too
    if (req.body?.finalize) {
      db.get('golf_tournaments').find({ id: tournamentId }).assign({ results_entered: true }).write();
    }

    res.json({ success: true, eventName: event.name, updated: updated.length, notFound, results, syncTime: now(), finalized: Boolean(req.body?.finalize) });
  } catch (err) {
    console.error('ESPN sync error:', err);
    res.status(500).json({ error: 'ESPN sync failed: ' + err.message });
  }
});

// ─── Settings ─────────────────────────────────────────────────────────────────
app.get('/api/settings', auth, adminOnly, (req, res) => {
  const s = db.get('settings').value();
  res.json({ has_smtp: Boolean(s.smtp_host && s.smtp_user) });
});

app.put('/api/settings', auth, adminOnly, (req, res) => {
  const { smtp_host, smtp_port, smtp_user, smtp_password } = req.body || {};
  if (smtp_host !== undefined) db.get('settings').assign({ smtp_host: smtp_host || '' }).write();
  if (smtp_port !== undefined) db.get('settings').assign({ smtp_port: smtp_port }).write();
  if (smtp_user !== undefined) db.get('settings').assign({ smtp_user: smtp_user || '' }).write();
  if (smtp_password !== undefined) db.get('settings').assign({ smtp_password: smtp_password || '' }).write();
  initEmail();
  res.json({ success: true });
});

// ─── External APIs ────────────────────────────────────────────────────────────
app.get('/api/external/golf-events', auth, adminOnly, async (req, res) => {
  const s = db.get('settings').value();
  const apiKey = s.live_golf_api_key;
  if (!apiKey) return res.status(400).json({ error: 'Set your Live Golf API key in Admin → API Settings first.' });
  try {
    const params = new URLSearchParams({ api_key: apiKey });
    if (req.query.start_date) params.set('start_date', req.query.start_date);
    if (req.query.end_date) params.set('end_date', req.query.end_date);
    if (req.query.tour) params.set('tour', req.query.tour);
    const response = await fetch('https://use.livegolfapi.com/v1/events?' + params);
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      return res.status(response.status).json({ error: err.message || 'Live Golf API error' });
    }
    const data = await response.json();
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch golf events: ' + err.message });
  }
});

app.get('/api/external/epl-results', auth, adminOnly, async (req, res) => {
  res.status(410).json({ error: 'This endpoint is deprecated. EPL data now comes from ESPN on the frontend.' });
});

app.get('/api/external/epl-fixtures', auth, adminOnly, async (req, res) => {
  res.status(410).json({ error: 'This endpoint is deprecated. EPL data now comes from ESPN on the frontend.' });
});

// Email settings & reminder system
let emailTransporter = null;

function initEmail() {
  const s = db.get('settings').value();
  if (s.smtp_host && s.smtp_user && s.smtp_password) {
    emailTransporter = require('nodemailer').createTransport({
      host: s.smtp_host,
      port: s.smtp_port || 587,
      secure: false,
      auth: { user: s.smtp_user, pass: s.smtp_password }
    });
  }
}

// Check for pending picks and send reminders every minute
setInterval(async () => {
  if (!emailTransporter || !dbReady) return;
  try {
    const now = new Date();
    const oneHourFromNow = new Date(now.getTime() + 60 * 60 * 1000);

    // Check golf tournaments
    const golfTournaments = db.get('golf_tournaments').value();
  for (const t of golfTournaments) {
    if (t.results_entered || !t.deadline) continue;
    const dl = new Date(t.deadline);
    if (dl > now && dl <= oneHourFromNow) {
      const picks = db.get('golf_picks').filter({ tournament_id: t.id }).value();
      const users = db.get('users').value();
      const pickedUserIds = new Set(picks.map(p => p.user_id));

      const usersWithoutPicks = users.filter(u => u.email && !pickedUserIds.has(u.id));
      for (const u of usersWithoutPicks) {
        try {
          await emailTransporter.sendMail({
            from: '"The Boys Picks" <noreply@theboyspicks.com>',
            to: u.email,
            subject: `⛳ Reminder: ${t.name} - 1 hour to pick!`,
            text: `Hi ${u.username},\n\nOnly 1 hour left to make your pick for ${t.name}!\n\nPick a golfer NOT in the predicted Top 5.\n\nGo to https://theboyspicks.com to make your pick.\n\nGood luck!`
          });
          console.log(`Reminder sent to ${u.email} for ${t.name}`);
        } catch (e) { console.error('Email failed:', e.message); }
      }
    }
  }

  // Check soccer weeks
  const soccerWeeks = db.get('soccer_weeks').value();
  for (const w of soccerWeeks) {
    if (w.results_entered || !w.deadline) continue;
    const dl = new Date(w.deadline);
    if (dl > now && dl <= oneHourFromNow) {
      const games = db.get('soccer_games').filter({ week_id: w.id }).value();
      const gameIds = games.map(g => g.id);
      const picks = db.get('soccer_picks').filter(p => gameIds.includes(p.game_id)).value();
      const users = db.get('users').value();
      const pickedUserIds = new Set(picks.map(p => p.user_id));

      const usersWithoutPicks = users.filter(u => u.email && !pickedUserIds.has(u.id));
      for (const u of usersWithoutPicks) {
        try {
          await emailTransporter.sendMail({
            from: '"The Boys Picks" <noreply@theboyspicks.com>',
            to: u.email,
            subject: `⚽ Reminder: ${w.week_name} - 1 hour to pick!`,
            text: `Hi ${u.username},\n\nOnly 1 hour left to make your picks for ${w.week_name}!\n\nGo to https://theboyspicks.com to make your 3 score predictions.\n\nGood luck!`
          });
          console.log(`Reminder sent to ${u.email} for ${w.week_name}`);
        } catch (e) { console.error('Email failed:', e.message); }
      }
    }
  }
  } catch (e) { console.error('Reminder loop error:', e.message); }
}, 60 * 1000); // Check every minute

// Wait for DB then start
function startServer() {
  if (!dbReady) {
    setTimeout(startServer, 500);
    return;
  }
  initEmail();
  app.listen(PORT, () => console.log('Picks app running on http://localhost:' + PORT));
}

startServer();
