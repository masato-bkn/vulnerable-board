require 'sinatra'
require 'sinatra/reloader' if development?
require 'sqlite3'
require 'securerandom'

# DB設定
DB_PATH = File.join(__dir__, 'db', 'board.db')

def db
  conn = SQLite3::Database.new(DB_PATH)
  conn.results_as_hash = true
  conn
end

# セッション設定（学習用に簡易実装）
enable :sessions
set :session_secret, 'super_secret_key_for_learning'

# ========================================
# ヘルパー
# ========================================
helpers do
  def current_user
    return nil unless session[:user_id]
    db.execute("SELECT * FROM users WHERE id = ?", session[:user_id]).first
  end

  def logged_in?
    !current_user.nil?
  end
end

# ========================================
# トップページ → 投稿一覧へリダイレクト
# ========================================
get '/' do
  redirect '/posts'
end

# ========================================
# ユーザー登録
# ========================================
get '/register' do
  @error = nil
  erb :register
end

post '/register' do
  username = params[:username]
  password = params[:password]

  if username.nil? || username.empty? || password.nil? || password.empty?
    @error = 'ユーザー名とパスワードを入力してください'
    return erb(:register)
  end

  begin
    db.execute("INSERT INTO users (username, password) VALUES (?, ?)", [username, password])
    redirect '/login'
  rescue SQLite3::ConstraintException
    @error = 'そのユーザー名は既に使われています'
    erb :register
  end
end

# ========================================
# ログイン（★ 脆弱な実装 - SQLインジェクション）
# ========================================
get '/login' do
  @error = nil
  erb :login
end

post '/login' do
  username = params[:username]
  password = params[:password]

  # ★★★ 脆弱なコード ★★★
  # ユーザー入力を直接SQL文に埋め込んでいる！
  query = "SELECT * FROM users WHERE username = '#{username}' AND password = '#{password}'"
  puts "[DEBUG] SQL: #{query}"  # デバッグ用にSQL文を出力

  user = db.execute(query).first

  if user
    session[:user_id] = user['id']
    redirect '/posts'
  else
    @error = 'ユーザー名またはパスワードが間違っています'
    erb :login
  end
end

# ========================================
# ログアウト
# ========================================
get '/logout' do
  session.clear
  redirect '/login'
end

# ========================================
# 投稿一覧
# ========================================
get '/posts' do
  unless logged_in?
    redirect '/login'
    return
  end

  @posts = db.execute(<<-SQL)
    SELECT posts.*, users.username
    FROM posts
    JOIN users ON posts.user_id = users.id
    ORDER BY posts.created_at DESC
  SQL

  @user = current_user
  erb :posts
end

# ========================================
# 投稿作成
# ========================================
post '/posts' do
  redirect '/login' unless logged_in?

  body = params[:body]
  return redirect('/posts') if body.nil? || body.strip.empty?

  db.execute("INSERT INTO posts (user_id, body) VALUES (?, ?)", [session[:user_id], body])
  redirect '/posts'
end

# ========================================
# 投稿削除
# ========================================
post '/posts/:id/delete' do
  redirect '/login' unless logged_in?

  db.execute("DELETE FROM posts WHERE id = ? AND user_id = ?", [params[:id], session[:user_id]])
  redirect '/posts'
end

# ========================================
# プロフィール
# ========================================
get '/profile' do
  redirect '/login' unless logged_in?
  @user = current_user
  erb :profile
end
