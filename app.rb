# =============================================================================
# 脆弱性学習用 掲示板アプリ - メインアプリケーション
#
# Sinatraベースの掲示板。意図的に脆弱性を含んでおり、
# 攻撃→理解→防御のサイクルで学習するためのもの。
#
# 【含まれる脆弱性】
#   第1回: SQLインジェクション（ログイン処理）
#   第2回: XSS（投稿表示）
#   第3回: CSRF（投稿削除）
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
#
# 【第3回との関連: SameSite Cookie属性】
# ここではSameSite属性を明示的に設定していない。
# 最近のブラウザはデフォルトで SameSite=Lax を適用し、
# 別オリジンからのPOSTリクエストにCookieを付与しない。
# そのため、罠ページが別ドメインにある場合はCSRFが成立しないことがある。
# 学習用に同一ドメイン（localhost:4567）から罠ページを配信しているのはこのため。
# 本番アプリでは SameSite=Lax に加えてCSRFトークンも使う「多層防御」が推奨される。
# =============================================================================
enable :sessions
set :session_secret, 'this_is_a_super_secret_key_for_learning_vulnerable_board_app_2024!'

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
#   SQL文の組み立てを図で見ると:
#
#     元のSQL:  ... username = '________' AND password = '________'
#                                ↑        ↑
#                         ここにユーザー入力が入る
#
#     攻撃入力:                ' OR 1=1 --
#
#     結果:     ... username = '' OR 1=1 --' AND password = '...'
#                    ├─空文字─┘  ├true─┘ ├──コメント化──────────┘
#                    false        true
#
#     → false OR true = true → 全行がヒット → 最初の1件(admin)でログイン
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
#
#   プレースホルダ（?）を使うと、入力は「SQL構文」ではなく「ただの値」として
#   処理されるため、' OR 1=1 -- はそのまま文字列として検索される。
#   → そんなユーザー名は存在しない → ログイン失敗 → 攻撃が防がれる
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
#
# 【第2回 学習対象: XSS（クロスサイトスクリプティング）】
#
# 脆弱な理由:
#   ビュー（posts.erb）で投稿内容を <%= post['body'] %> でそのまま出力している。
#   SinatraのERBでは <%= ... %> はHTMLエスケープを行わないため、
#   ユーザーが入力した <script> タグなどがブラウザでそのまま実行される。
#
#   ※ 脆弱性はビュー側（posts.erb）にあるが、サーバー側でもエスケープ処理を
#     行っていないため、入力がそのままDBに保存され、そのままHTMLに出力される。
#
# 攻撃例:
#   投稿欄に以下を入力:
#     <script>alert('XSS')</script>
#
#   → 投稿一覧を表示した全ユーザーのブラウザでアラートが表示される
#   → Cookie窃取スクリプトを仕込めば、セッションハイジャックも可能
#
# 防御方法（修正時に適用）:
#   方法1: ビュー側でエスケープ
#     <%= Rack::Utils.escape_html(post['body']) %>
#
#   方法2: ヘルパーメソッドを定義してエスケープ
#     helpers do
#       def h(text)
#         Rack::Utils.escape_html(text)
#       end
#     end
#     → ビューで <%= h(post['body']) %> と使う
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
#
# 投稿内容をエスケープ・サニタイズせずにそのままDBに保存している。
# これはXSS学習のために意図的にそうしている。
# 保存時にエスケープしない理由:
#   - 出力時エスケープが正しいアプローチ（保存時は原文を保持すべき）
#   - ただし、出力時もエスケープしていないため、XSSが成立する
# =============================================================================

# 新しい投稿をDBに保存
# ※ このエンドポイントにもCSRFトークン検証がない。
#   罠サイトから勝手に投稿を作成させる攻撃も理論上は可能。
#   （第3回では削除にフォーカスしているが、すべてのPOSTエンドポイントが対象）
post '/posts' do
  redirect '/login' unless logged_in?

  body = params[:body]
  return redirect('/posts') if body.nil? || body.strip.empty?

  # プレースホルダを使った安全なINSERT（SQLインジェクション対策済み）
  db.execute("INSERT INTO posts (user_id, body) VALUES (?, ?)", [session[:user_id], body])
  redirect '/posts'
end

# =============================================================================
# ルーティング: 投稿削除
#
# 【第3回 学習対象: CSRF（クロスサイトリクエストフォージェリ）】
#
# 【CSRFという名前の意味】
#   Cross-Site  : 別サイト（罠サイト）から
#   Request     : リクエスト（削除や投稿などの操作要求）を
#   Forgery     : 偽造する（本人のふりをして送りつける）
#   → 「別サイトからリクエストを偽造する」攻撃
#
# 【なぜブラウザはCookieを自動送信するのか】
#   Cookieは「ドメインに紐づいたデータ」として設計されており、
#   HTTP仕様上「そのドメインへのリクエスト時は必ずCookieを付ける」と定められている。
#   これはもともとログイン維持などのユーザー利便性のための仕様だが、
#   ブラウザは送信元（罠サイトか正規サイトか）を区別せずにCookieを付けるため
#   CSRF攻撃に悪用される。便利さとセキュリティのトレードオフが生んだ問題。
#
# 脆弱な理由:
#   CSRFトークンの検証を行っていないため、外部の罠サイトから
#   ログイン中ユーザーの操作を偽装できる。
#
# 攻撃例:
#   1. 攻撃者が罠ページ（csrf_trap.html）を用意する
#   2. 罠ページには掲示板の削除エンドポイントにPOSTするフォームがある
#   3. ログイン中のユーザーが罠ページのボタンをクリックする
#   4. ブラウザはPOSTリクエストと一緒にセッションCookieを自動送信する
#   5. サーバーはCSRFトークンを検証しないため、正規のリクエストと区別できない
#   6. ユーザーの投稿が意図せず削除される
#
# 仕組み:
#   ブラウザは、送信先ドメインのCookieをリクエストに自動付与する。
#   つまり、罠サイトからlocalhost:4567へのPOSTリクエストにも、
#   掲示板アプリのセッションCookieが付く。
#   サーバーから見ると「ログイン済みユーザーからの正規リクエスト」に見える。
#
#   正規の削除:
#     ユーザー → 掲示板の削除ボタン → POST /posts/1/delete（+Cookie）→ サーバー
#
#   CSRF攻撃:
#     ユーザー → 罠ページのボタン → POST /posts/1/delete（+Cookie自動付与）→ サーバー
#     ※ サーバーにはどちらも同じに見える！
#
# 防御方法（修正時に適用）:
#   CSRFトークン（ランダムな秘密値）をセッションとフォームの両方に持たせ、
#   リクエスト時に一致するか検証する。
#
#   1. フォーム描画時にトークンを生成し、hidden フィールドとセッションに保存:
#      session[:csrf_token] = SecureRandom.hex(32)
#      <input type="hidden" name="csrf_token" value="<%= session[:csrf_token] %>">
#
#   2. POSTリクエスト受信時にトークンを検証:
#      halt 403, 'CSRF token mismatch' unless params[:csrf_token] == session[:csrf_token]
#
#   罠サイトは被害者のセッションに保存されたトークンの値を知ることができないため、
#   正しいトークンをフォームに含めることができず、攻撃が失敗する。
#
# 【CSRFトークンは開発者ツールで見えるが問題ない理由】
#   ブラウザの開発者ツール（ElementsタブやNetworkタブ）でトークンの値は確認できる。
#   しかし「自分のブラウザで自分のセッションのトークンを見る」だけであり問題ない。
#
#   攻撃者が欲しいのは「被害者のセッションに紐づいたトークン」。
#   これは同一オリジンポリシー（Same-Origin Policy）によって守られている:
#
#     ✅ 罠サイト → 掲示板にリクエストを「送る」ことはできる
#     ❌ 罠サイト → 掲示板のHTMLレスポンスを「読む」ことはできない
#
#   フォームに埋め込まれたトークンを取得するにはHTMLを読む必要があるが、
#   別オリジンからはそれが禁止されているため、攻撃者はトークンを知ることができない。
# =============================================================================

# 投稿を削除（自分の投稿のみ）（★ CSRFトークン検証なし）
post '/posts/:id/delete' do
  redirect '/login' unless logged_in?

  # ★ 本来ここでCSRFトークンを検証すべき:
  #   halt 403, 'CSRF token mismatch' unless params[:csrf_token] == session[:csrf_token]
  # この検証がないため、罠サイトからのリクエストでも削除が実行されてしまう

  # WHERE句でuser_idも指定し、他人の投稿は削除できないようにしている
  # → 認可チェック（自分の投稿のみ削除可）はできているが、
  #   リクエストの出所チェック（CSRF対策）ができていない
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

# =============================================================================
# ルーティング: アイコンアップロード
#
# 【第4回 学習対象: ディレクトリトラバーサル】
#
# 脆弱な理由:
#   params[:file][:filename] をそのままパスに使っており、
#   ../../views/posts.erb のようなパス成分を含むファイル名を
#   検証も除去もしていない。
#   結果として upload_dir 外の任意のファイルを上書きできる。
#
# 防御方法:
#   1. File.basename でパス成分を除去する:
#      filename = File.basename(params[:file][:filename])
#
#   2. SecureRandom.hex でランダムなファイル名を生成する（推奨）:
#      ext = File.extname(params[:file][:filename])
#      filename = SecureRandom.hex(16) + ext
#
#   3. Pathname#cleanpath で保存先ディレクトリ外を拒否する:
#      save_path = File.expand_path(filename, upload_dir)
#      halt 400, '不正なファイル名です' unless save_path.start_with?(upload_dir)
# =============================================================================

post '/profile/upload' do
  redirect '/login' unless logged_in?

  uploaded = params[:file]
  return redirect('/profile') if uploaded.nil?

  # ★★★ 脆弱なコード ★★★
  # ファイル名をそのままパスに使っている。
  # ../../views/posts.erb のようなファイル名を渡すと
  # upload_dir 外のファイルを上書きできてしまう。
  filename = uploaded[:filename]
  upload_dir = File.join(__dir__, 'public', 'uploads')
  save_path = File.join(upload_dir, filename)

  puts "[DEBUG] filename : #{filename}"
  puts "[DEBUG] save_path: #{save_path}"

  # ディレクトリ外チェックなし — 任意のパスに書き込まれる
  File.write(save_path, uploaded[:tempfile].read)

  # DB の icon_path を更新（通常のアップロード時に表示するため）
  db.execute("UPDATE users SET icon_path = ? WHERE id = ?", [filename, session[:user_id]])

  redirect '/profile'
end
