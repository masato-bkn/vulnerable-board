# =============================================================================
# 脆弱性学習用 掲示板アプリ - メインアプリケーション
#
# Sinatraベースの掲示板。意図的に脆弱性を含んでおり、
# 攻撃→理解→防御のサイクルで学習するためのもの。
#
# 【含まれる脆弱性】
#   第1回: SQLインジェクション（ログイン処理）
#   第2回: XSS（投稿表示）  ※未実装
#   第3回: CSRF（投稿削除）  ※未実装
#   第4回: ディレクトリトラバーサル（アイコンアップロード）  ※未実装
#   第5回: 認証の不備（セッション管理）  ※未実装
# =============================================================================

require 'sinatra'
require 'sinatra/reloader' if development?
require 'sqlite3'
require 'securerandom'

# =============================================================================
# データベース設定
# =============================================================================

# SQLiteのDBファイルパス（db/board.db）
DB_PATH = File.join(__dir__, 'db', 'board.db')

# DBコネクションを返すヘルパー
# results_as_hash = true により、クエリ結果をカラム名をキーとしたHashで取得できる
# 例: row['username'] のようにアクセス可能
def db
  conn = SQLite3::Database.new(DB_PATH)
  conn.results_as_hash = true
  conn
end

# =============================================================================
# セッション設定
#
# Sinatraの組み込みセッション機能を使用。
# session_secret はセッションCookieの署名に使われる秘密鍵。
# 本番では推測困難なランダム値を使うべきだが、学習用に固定値にしている。
# =============================================================================
enable :sessions
set :session_secret, 'super_secret_key_for_learning'

# =============================================================================
# ヘルパーメソッド
# ビューとルーティングの両方から使用できる共通処理
# =============================================================================
helpers do
  # セッションに保存されたuser_idからユーザー情報を取得
  # ログインしていなければnilを返す
  # ※ プレースホルダ（?）を使った安全なクエリ
  def current_user
    return nil unless session[:user_id]
    db.execute("SELECT * FROM users WHERE id = ?", session[:user_id]).first
  end

  # ログイン状態を判定
  def logged_in?
    !current_user.nil?
  end
end

# =============================================================================
# ルーティング: トップページ
# =============================================================================

# トップページは掲示板（投稿一覧）へリダイレクト
get '/' do
  redirect '/posts'
end

# =============================================================================
# ルーティング: ユーザー登録
#
# 登録処理ではプレースホルダ（?）を使っており、SQLインジェクションは発生しない。
# ログインとの実装の違いを比較して、安全な書き方を確認できる。
# =============================================================================

# ユーザー登録フォーム表示
get '/register' do
  @error = nil
  erb :register
end

# ユーザー登録処理
post '/register' do
  username = params[:username]
  password = params[:password]

  # バリデーション: 空値チェック
  if username.nil? || username.empty? || password.nil? || password.empty?
    @error = 'ユーザー名とパスワードを入力してください'
    return erb(:register)
  end

  begin
    # プレースホルダ（?）を使った安全なSQL
    # ユーザー入力がSQL構文として解釈されることはない
    db.execute("INSERT INTO users (username, password) VALUES (?, ?)", [username, password])
    redirect '/login'
  rescue SQLite3::ConstraintException
    # usersテーブルのusername列にUNIQUE制約があるため、重複時にここに来る
    @error = 'そのユーザー名は既に使われています'
    erb :register
  end
end

# =============================================================================
# ルーティング: ログイン
#
# 【第1回 学習対象: SQLインジェクション】
#
# 脆弱な理由:
#   ユーザー入力（username, password）を文字列補間（#{...}）で
#   直接SQL文に埋め込んでいる。攻撃者はSQL構文を注入できる。
#
# 攻撃例:
#   ユーザー名: ' OR 1=1 --
#   パスワード: （何でも）
#
#   生成されるSQL:
#     SELECT * FROM users WHERE username = '' OR 1=1 --' AND password = '...'
#
#   解説:
#   - ' でusernameの文字列リテラルを閉じる
#   - OR 1=1 で常に真になる条件を追加
#   - -- 以降はSQLコメントとなり、パスワード検証が無視される
#   - 結果: テーブルの最初のユーザー（通常admin）としてログインできる
#
# 防御方法（修正時に適用）:
#   プレースホルダを使ったパラメータバインドに変更する
#   db.execute("SELECT * FROM users WHERE username = ? AND password = ?", [username, password])
# =============================================================================

# ログインフォーム表示
get '/login' do
  @error = nil
  erb :login
end

# ログイン処理（★ 脆弱な実装）
post '/login' do
  username = params[:username]
  password = params[:password]

  # ★★★ 脆弱なコード ★★★
  # 文字列補間（#{...}）でユーザー入力を直接SQL文に埋め込んでいる！
  # これにより、攻撃者がSQL構文を注入（インジェクション）できてしまう
  query = "SELECT * FROM users WHERE username = '#{username}' AND password = '#{password}'"
  puts "[DEBUG] SQL: #{query}"  # ターミナルに実行されるSQLを表示（攻撃の確認用）

  user = db.execute(query).first

  if user
    # 認証成功: セッションにユーザーIDを保存してログイン状態にする
    session[:user_id] = user['id']
    redirect '/posts'
  else
    @error = 'ユーザー名またはパスワードが間違っています'
    erb :login
  end
end

# =============================================================================
# ルーティング: ログアウト
# =============================================================================

# セッションを全クリアしてログイン画面へ
get '/logout' do
  session.clear
  redirect '/login'
end

# =============================================================================
# ルーティング: 投稿一覧
# =============================================================================

# 掲示板の投稿一覧を表示（ログイン必須）
get '/posts' do
  unless logged_in?
    redirect '/login'
    return
  end

  # postsテーブルとusersテーブルをJOINして、投稿者名付きで取得
  # 新しい投稿が上に来るように降順ソート
  @posts = db.execute(<<-SQL)
    SELECT posts.*, users.username
    FROM posts
    JOIN users ON posts.user_id = users.id
    ORDER BY posts.created_at DESC
  SQL

  @user = current_user
  erb :posts
end

# =============================================================================
# ルーティング: 投稿作成
# =============================================================================

# 新しい投稿をDBに保存
post '/posts' do
  redirect '/login' unless logged_in?

  body = params[:body]
  return redirect('/posts') if body.nil? || body.strip.empty?

  # プレースホルダを使った安全なINSERT
  db.execute("INSERT INTO posts (user_id, body) VALUES (?, ?)", [session[:user_id], body])
  redirect '/posts'
end

# =============================================================================
# ルーティング: 投稿削除
#
# 現状、自分の投稿のみ削除可能（user_id条件で制限）。
# ただし、CSRFトークンのチェックがないため、
# 第3回でCSRF攻撃の対象となる。
# =============================================================================

# 投稿を削除（自分の投稿のみ）
post '/posts/:id/delete' do
  redirect '/login' unless logged_in?

  # WHERE句でuser_idも指定し、他人の投稿は削除できないようにしている
  db.execute("DELETE FROM posts WHERE id = ? AND user_id = ?", [params[:id], session[:user_id]])
  redirect '/posts'
end

# =============================================================================
# ルーティング: プロフィール
# 第4回でアイコンアップロード機能を追加予定
# =============================================================================

get '/profile' do
  redirect '/login' unless logged_in?
  @user = current_user
  erb :profile
end
