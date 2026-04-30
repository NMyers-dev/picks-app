// db-adapter.js
// Custom lowdb adapter that persists the entire database as a single
// document in MongoDB. The whole DB is loaded into memory at startup
// (so reads stay synchronous, exactly like the old FileSync adapter)
// and pushed back to MongoDB on every .write() call.
//
// Why a "single document" instead of one MongoDB collection per entity?
// It lets us migrate from the JSON-file storage with ZERO route-handler
// changes — lowdb's API stays exactly the same. The whole state is well
// under MongoDB's 16 MB document limit.

const { MongoClient } = require('mongodb');

const FALLBACK_DEFAULTS = {
  users: [],
  golf_tournaments: [],
  golf_picks: [],
  soccer_weeks: [],
  soccer_games: [],
  soccer_picks: [],
  settings: {}
};

class MongoSyncAdapter {
  constructor(collection, docId, initialState) {
    this.collection = collection;
    this.docId = docId;
    this._initialState = initialState;
    // Serialize writes so two near-simultaneous .write() calls can't
    // arrive at MongoDB out-of-order.
    this._writeChain = Promise.resolve();
    this._lastError = null;
  }

  // lowdb calls this once when low(adapter) is invoked.
  read() {
    return this._initialState;
  }

  // lowdb calls this on every .write(). MongoDB driver is async-only,
  // so we kick off the write fire-and-forget but chain it onto the
  // previous one to preserve order. Logs any errors.
  write(data) {
    const snapshot = JSON.parse(JSON.stringify(data));
    this._writeChain = this._writeChain
      .then(() =>
        this.collection.replaceOne(
          { _id: this.docId },
          { _id: this.docId, data: snapshot, updated_at: new Date() },
          { upsert: true }
        )
      )
      .then(() => { this._lastError = null; })
      .catch(err => {
        this._lastError = err;
        console.error('[MongoSyncAdapter] write failed:', err.message);
      });
    return true;
  }

  // Wait for any pending writes to complete (used on graceful shutdown).
  flush() {
    return this._writeChain;
  }
}

/**
 * Connect to MongoDB and return { adapter, client, flush, lastError }.
 * Throws if MONGODB_URI is missing or connection fails.
 *
 * @param {object} options
 * @param {string} options.uri - MongoDB connection string
 * @param {string} [options.dbName='picks_app'] - DB name
 * @param {string} [options.collectionName='app_state'] - Collection name
 * @param {string} [options.docId='main'] - The single doc's _id
 * @param {object} [options.defaults] - Default schema if no doc exists yet
 */
async function createMongoAdapter({
  uri,
  dbName = 'picks_app',
  collectionName = 'app_state',
  docId = 'main',
  defaults = FALLBACK_DEFAULTS
} = {}) {
  if (!uri) throw new Error('MONGODB_URI is required');

  const client = new MongoClient(uri, {
    // Reasonable timeouts; Railway+Atlas should answer within a couple seconds.
    serverSelectionTimeoutMS: 10000,
    connectTimeoutMS: 10000
  });
  await client.connect();
  const collection = client.db(dbName).collection(collectionName);

  // Ensure the document exists (seed with defaults on first deploy).
  const existing = await collection.findOne({ _id: docId });
  let initialState;
  if (existing && existing.data) {
    initialState = existing.data;
    console.log('[DB] Loaded existing state from MongoDB.');
  } else {
    initialState = JSON.parse(JSON.stringify(defaults));
    await collection.replaceOne(
      { _id: docId },
      { _id: docId, data: initialState, updated_at: new Date() },
      { upsert: true }
    );
    console.log('[DB] Seeded fresh state in MongoDB.');
  }

  // Make sure every expected key exists (in case schema grew over time).
  for (const key of Object.keys(defaults)) {
    if (initialState[key] === undefined) initialState[key] = defaults[key];
  }

  const adapter = new MongoSyncAdapter(collection, docId, initialState);
  return {
    adapter,
    client,
    flush: () => adapter.flush(),
    lastError: () => adapter._lastError
  };
}

module.exports = { createMongoAdapter, MongoSyncAdapter, FALLBACK_DEFAULTS };
