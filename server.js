const express = require('express');
const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production-set-JWT_SECRET-env-var';

// ─── Database ────────────────────────────────────────────────────────────────
const adapter = new FileSync(process.env.DB_PATH || 'picks.json');
const db = low(adapter);

db.defaults({
  users: [],
  golf_tournaments: [],
  golf_picks: [],
  soccer_weeks: [],
  soccer_games: [],
  soccer_picks: [],
  settings: {}
}).write();

// Migration: ensure is_super_admin exists on all users
const users = db.get('users').value();
users.forEach((u, i) => {
  if (u.is_super_admin === undefined) {
    db.get('users').find({ id: u.id }).assign({ is_super_admin: i === 0 }).write();
  }
});

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
    id: u.id, username: u.username, email: u.email, is_admin: u.is_admin, created_at: u.created_at
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

// ─── Golf Tournaments ─────────────────────────────────────────────────────────
app.get('/api/golf/tournaments', auth, (req, res) => {
  const tournaments = db.get('golf_tournaments').orderBy('created_at', 'desc').value();
  const myPicks = db.get('golf_picks').filter({ user_id: req.user.id }).value();
  const pickMap = Object.fromEntries(myPicks.map(p => [p.tournament_id, p]));

  res.json(tournaments.map(t => ({
    ...t,
    my_pick: pickMap[t.id] ? {
      picked_golfer: pickMap[t.id].picked_golfer,
      result_category: pickMap[t.id].result_category,
      points_earned: pickMap[t.id].points_earned
    } : null
  })));
});

app.post('/api/golf/tournaments', auth, adminOnly, (req, res) => {
  const { name, course, start_date, deadline, predicted_top5, event_type } = req.body || {};
  if (!name?.trim()) return res.status(400).json({ error: 'Tournament name required' });
  if (!Array.isArray(predicted_top5) || predicted_top5.length !== 5 || predicted_top5.some(g => !g?.trim()))
    return res.status(400).json({ error: 'Exactly 5 predicted top golfers required' });
  if (!['regular','signature','major'].includes(event_type))
    return res.status(400).json({ error: 'Event type must be regular, signature, or major' });

  const tournament = {
    id: nextId('golf_tournaments'),
    name: name.trim(),
    course: course?.trim() || null,
    start_date: start_date || null,
    deadline: deadline || null,
    predicted_top5: predicted_top5.map(g => g.trim()),
    event_type: event_type || 'regular',
    results_entered: false,
    created_at: now()
  };

  db.get('golf_tournaments').push(tournament).write();
  res.json({ id: tournament.id });
});

app.delete('/api/golf/tournaments/:id', auth, adminOnly, (req, res) => {
  const id = parseInt(req.params.id);
  db.get('golf_picks').remove({ tournament_id: id }).write();
  db.get('golf_tournaments').remove({ id }).write();
  res.json({ success: true });
});

app.get('/api/golf/tournaments/:id/picks', auth, (req, res) => {
  const tournamentId = parseInt(req.params.id);
  const tournament = db.get('golf_tournaments').find({ id: tournamentId }).value();
  const picks = db.get('golf_picks').filter({ tournament_id: tournamentId }).value();
  const users = db.get('users').value();

  // Hide other users' picks until deadline or results entered
  const deadlinePassed = tournament && (tournament.results_entered || (tournament.deadline && new Date() >= new Date(tournament.deadline)));
  if (!deadlinePassed) {
    const myPicks = picks.filter(p => p.user_id === req.user.id);
    const user = users.find(u => u.id === req.user.id);
    return res.json(myPicks.map(p => ({ id: p.id, picked_golfer: p.picked_golfer, result_category: p.result_category, points_earned: p.points_earned, username: user?.username })));
  }

  const result = picks.map(p => {
    const user = users.find(u => u.id === p.user_id);
    return { id: p.id, picked_golfer: p.picked_golfer, result_category: p.result_category, points_earned: p.points_earned, username: user?.username };
  }).sort((a, b) => (b.points_earned || 0) - (a.points_earned || 0));

  res.json(result);
});

app.post('/api/golf/tournaments/:id/pick', auth, (req, res) => {
  const { picked_golfer } = req.body || {};
  if (!picked_golfer?.trim()) return res.status(400).json({ error: 'Golfer name required' });

  const tournamentId = parseInt(req.params.id);
  const tournament = db.get('golf_tournaments').find({ id: tournamentId }).value();
  if (!tournament) return res.status(404).json({ error: 'Tournament not found' });
  if (tournament.results_entered) return res.status(400).json({ error: 'Results already entered — picks are locked' });

  if (tournament.predicted_top5.some(g => g.toLowerCase() === picked_golfer.trim().toLowerCase()))
    return res.status(400).json({ error: `${picked_golfer.trim()} is in the predicted Top 5 — you must pick someone else!` });

  const existing = db.get('golf_picks').find({ tournament_id: tournamentId, user_id: req.user.id }).value();
  if (existing) {
    db.get('golf_picks').find({ id: existing.id }).assign({ picked_golfer: picked_golfer.trim(), result_category: null, points_earned: 0 }).write();
  } else {
    db.get('golf_picks').push({
      id: nextId('golf_picks'),
      tournament_id: tournamentId,
      user_id: req.user.id,
      picked_golfer: picked_golfer.trim(),
      result_category: null,
      points_earned: 0,
      created_at: now()
    }).write();
  }

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

app.get('/api/golf/leaderboard', auth, (req, res) => {
  const users = db.get('users').value();
  const allPicks = db.get('golf_picks').value();

  const leaderboard = users.map(u => {
    const picks = allPicks.filter(p => p.user_id === u.id);
    return {
      id: u.id,
      username: u.username,
      total_points: picks.reduce((s, p) => s + (p.points_earned || 0), 0),
      total_picks: picks.length,
      wins:   picks.filter(p => p.result_category === 'winner').length,
      top5s:  picks.filter(p => ['winner','top5'].includes(p.result_category)).length,
      top10s: picks.filter(p => ['winner','top5','top10'].includes(p.result_category)).length,
      results_recorded: picks.filter(p => p.result_category).length
    };
  }).sort((a, b) => b.total_points - a.total_points || b.wins - a.wins || b.top5s - a.top5s);

  res.json(leaderboard);
});

// ─── Soccer Weeks ─────────────────────────────────────────────────────────────
app.get('/api/soccer/weeks', auth, (req, res) => {
  const weeks = db.get('soccer_weeks').orderBy('created_at', 'desc').value();
  const allGames = db.get('soccer_games').value();
  const myPicks = db.get('soccer_picks').filter({ user_id: req.user.id }).value();
  const picksByGame = Object.fromEntries(myPicks.map(p => [p.game_id, p]));

  res.json(weeks.map(w => ({
    ...w,
    games: allGames
      .filter(g => g.week_id === w.id)
      .sort((a, b) => a.game_order - b.game_order)
      .map(g => ({ ...g, my_pick: picksByGame[g.id] || null }))
  })));
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

app.delete('/api/soccer/weeks/:id', auth, superAdminOnly, (req, res) => {
  const weekId = parseInt(req.params.id);
  const games = db.get('soccer_games').filter({ week_id: weekId }).value();
  games.forEach(g => db.get('soccer_picks').remove({ game_id: g.id }).write());
  db.get('soccer_games').remove({ week_id: weekId }).write();
  db.get('soccer_weeks').remove({ id: weekId }).write();
  res.json({ success: true });
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

app.get('/api/soccer/leaderboard', auth, (req, res) => {
  const users = db.get('users').value();
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

// ─── Settings ─────────────────────────────────────────────────────────────────
app.get('/api/settings', auth, adminOnly, (req, res) => {
  const s = db.get('settings').value();
  res.json({ has_football_api_key: Boolean(s.football_data_api_key), has_live_golf_api_key: Boolean(s.live_golf_api_key) });
});

app.put('/api/settings', auth, adminOnly, (req, res) => {
  const { football_data_api_key, live_golf_api_key } = req.body || {};
  if (football_data_api_key !== undefined) db.get('settings').assign({ football_data_api_key: football_data_api_key || '' }).write();
  if (live_golf_api_key !== undefined) db.get('settings').assign({ live_golf_api_key: live_golf_api_key || '' }).write();
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

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`🏌️⚽  Picks app running on http://localhost:${PORT}`));
