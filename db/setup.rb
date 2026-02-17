# =============================================================================
# データベース初期化スクリプト
#
# SQLiteデータベースの作成とテーブル定義、初期データの投入を行う。
# 実行方法: ruby db/setup.rb
#
# テーブル構成:
#   - users: ユーザー情報（ログイン認証、プロフィール）
#   - posts: 掲示板の投稿データ
# =============================================================================

require 'sqlite3'

# DBファイルはこのスクリプトと同じディレクトリ（db/）に作成される
DB_PATH = File.join(__dir__, 'board.db')

def setup_database
  db = SQLite3::Database.new(DB_PATH)
  db.results_as_hash = true

  # ---------------------------------------------------------------------------
  # usersテーブル
  #
  # 【学習ポイント】
  # - password をプレーンテキストで保存している（本番ではbcrypt等でハッシュ化すべき）
  # - icon_path は第4回（ディレクトリトラバーサル）で使用予定
  # ---------------------------------------------------------------------------
  db.execute <<-SQL
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      icon_path TEXT DEFAULT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  SQL

  # ---------------------------------------------------------------------------
  # postsテーブル
  #
  # user_id で投稿者を参照。外部キーでusersテーブルと紐付け。
  # ---------------------------------------------------------------------------
  db.execute <<-SQL
    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      body TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
  SQL

  # ---------------------------------------------------------------------------
  # 初期データ: テスト用ユーザー
  #
  # INSERT OR IGNORE により、既にユーザーが存在する場合はスキップ。
  # 再実行してもデータが重複しない。
  # ---------------------------------------------------------------------------
  db.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'password123')")
  db.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('alice', 'alice456')")

  # ---------------------------------------------------------------------------
  # 初期データ: テスト用投稿
  #
  # postsテーブルが空の場合のみ、adminユーザーの投稿を1件作成。
  # ---------------------------------------------------------------------------
  admin = db.execute("SELECT id FROM users WHERE username = 'admin'").first
  if admin && db.execute("SELECT COUNT(*) as c FROM posts").first['c'] == 0
    db.execute("INSERT INTO posts (user_id, body) VALUES (?, 'こんにちは！掲示板へようこそ。')", admin['id'])
  end

  db.close
  puts "Database initialized at #{DB_PATH}"
end

# このファイルが直接実行された場合のみsetup_databaseを呼ぶ
# （app.rb から require された場合は実行しない）
if __FILE__ == $0
  setup_database
end
