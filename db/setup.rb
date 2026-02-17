require 'sqlite3'

DB_PATH = File.join(__dir__, 'board.db')

def setup_database
  db = SQLite3::Database.new(DB_PATH)
  db.results_as_hash = true

  db.execute <<-SQL
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      icon_path TEXT DEFAULT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  SQL

  db.execute <<-SQL
    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      body TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
  SQL

  # テスト用ユーザーを作成（既に存在する場合はスキップ）
  db.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'password123')")
  db.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('alice', 'alice456')")

  # テスト用投稿
  admin = db.execute("SELECT id FROM users WHERE username = 'admin'").first
  if admin && db.execute("SELECT COUNT(*) as c FROM posts").first['c'] == 0
    db.execute("INSERT INTO posts (user_id, body) VALUES (?, 'こんにちは！掲示板へようこそ。')", admin['id'])
  end

  db.close
  puts "Database initialized at #{DB_PATH}"
end

if __FILE__ == $0
  setup_database
end
