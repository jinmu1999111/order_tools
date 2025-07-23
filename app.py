import os
import datetime
import secrets
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func, desc, and_
import pytz
from collections import defaultdict
from math import ceil

# --- アプリケーションとデータベースの初期設定 ---
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

db_url = os.environ.get('DATABASE_URL', 'sqlite:///instance/test.db')
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(hours=8)

if 'sqlite' in app.config['SQLALCHEMY_DATABASE_URI']:
    instance_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')
    os.makedirs(instance_path, exist_ok=True)

db = SQLAlchemy(app)
JST = pytz.timezone('Asia/Tokyo')

# --- ログイン機能の設定 ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "このページにアクセスするにはログインが必要です。"

# --- データベースモデルの定義 ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, default=True)
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

class MenuItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    active = db.Column(db.Boolean, default=True)
    popularity_count = db.Column(db.Integer, default=0)
    # ★★★ 修正点: 並び順を保存する列を追加 ★★★
    sort_order = db.Column(db.Integer, default=0, nullable=False)


class Table(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    status = db.Column(db.String(20), default='available')
    active_qr_token = db.Column(db.String(100), unique=True, nullable=True)
    qr_token_expiry = db.Column(db.DateTime(timezone=True), nullable=True)
    orders = db.relationship('Order', backref='table', lazy='dynamic', cascade="all, delete-orphan")

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(100), nullable=False)
    item_price = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='pending') # pending -> served -> cancelled
    timestamp = db.Column(db.DateTime(timezone=True), default=lambda: datetime.datetime.now(JST))
    table_id = db.Column(db.Integer, db.ForeignKey('table.id'), nullable=False)
    session_id = db.Column(db.String(100))

class TempQRToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(100), unique=True, nullable=False)
    table_name = db.Column(db.String(100))
    guest_count = db.Column(db.Integer)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.datetime.now(JST))
    used = db.Column(db.Boolean, default=False)
    def is_valid(self):
        if self.used: return False
        expiry = self.created_at + datetime.timedelta(minutes=30)
        return datetime.datetime.now(JST) < expiry

# --- ルートとロジック ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/qr/<token>')
def qr_auth(token):
    temp_token = TempQRToken.query.filter_by(token=token).first()
    if temp_token and temp_token.is_valid():
        table = Table.query.filter_by(name=temp_token.table_name).first()
        if not table:
            table = Table(name=temp_token.table_name)
            db.session.add(table)
            db.session.flush()
        session['table_id'] = table.id
        session['session_id'] = secrets.token_hex(16)
        table.status = 'occupied'
        temp_token.used = True
        db.session.commit()
        return redirect(url_for('table_menu', table_id=table.id))
    table = Table.query.filter_by(active_qr_token=token).first()
    if table and (not table.qr_token_expiry or table.qr_token_expiry > datetime.datetime.now(JST)):
        session['session_id'] = secrets.token_hex(16)
        session['table_id'] = table.id
        table.status = 'occupied'
        db.session.commit()
        return redirect(url_for('table_menu', table_id=table.id))
    flash('QRコードが無効か期限切れです。', 'danger')
    return redirect(url_for('index'))

# ★★★ 修正点: /table/<int:table_id>と共通のメニュー取得ロジック ★★★
def get_menu_data(sort_by='category'):
    if sort_by == 'popularity':
        items = MenuItem.query.filter_by(active=True).order_by(MenuItem.popularity_count.desc()).all()
        return {'items': items}
    else: # default to category
        menu_items = MenuItem.query.filter_by(active=True).order_by(MenuItem.category, MenuItem.sort_order).all()
        categorized_menu = defaultdict(list)
        for item in menu_items:
            categorized_menu[item.category].append(item)
        return {'categorized_menu': categorized_menu}

@app.route('/table/<int:table_id>')
def table_menu(table_id):
    if not session.get('table_id') == table_id and not (current_user and current_user.is_authenticated):
        abort(403)
    table = db.session.get(Table, table_id)
    if not table: abort(404)
    
    menu_data = get_menu_data()
    return render_template('table_menu.html', table=table, **menu_data)

# ★★★ 修正点: お客様メニューのソート用API ★★★
@app.route('/table/<int:table_id>/menu_partial')
def table_menu_partial(table_id):
    # 認証は省略（既にページにアクセスできている前提のため）
    sort_by = request.args.get('sort_by', 'category')
    menu_data = get_menu_data(sort_by)

    if sort_by == 'popularity':
        return render_template('_menu_popular.html', items=menu_data['items'])
    else:
        return render_template('_menu_category.html', categorized_menu=menu_data['categorized_menu'])


# --- 管理者ページ ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user, remember=True)
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        flash('ユーザー名またはパスワードが違います。', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('login'))

@app.route('/kitchen')
@login_required
def kitchen():
    return render_template('kitchen.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# ★★★ 修正点: メニュー管理画面の表示ロジック ★★★
@app.route('/admin/menu')
@login_required
def admin_menu():
    # カテゴリごとにグループ化してテンプレートに渡す
    menu_items_query = MenuItem.query.order_by(MenuItem.category, MenuItem.sort_order).all()
    categorized_items = defaultdict(list)
    for item in menu_items_query:
        categorized_items[item.category].append(item)
    return render_template('admin_menu.html', categorized_items=categorized_items)

@app.route('/admin/tables')
@login_required
def admin_tables():
    tables = Table.query.order_by(Table.name).all()
    return render_template('admin_tables.html', tables=tables)

@app.route('/admin/history')
@login_required
def admin_history():
    return render_template('admin_history.html', tables=Table.query.order_by(Table.name).all())

@app.route('/admin/guidance')
@login_required
def admin_guidance():
    return render_template('admin_guidance.html')

# --- APIエンドポイント ---
# (既存のAPIは省略)
# ...

# ★★★ 修正点: メニューの並び順を保存するAPI ★★★
@app.route('/api/menu/order', methods=['POST'])
@login_required
def update_menu_order():
    data = request.json
    item_ids = data.get('item_ids')
    if not item_ids:
        return jsonify(success=False, message="No item IDs provided"), 400

    try:
        for index, item_id in enumerate(item_ids):
            item = db.session.get(MenuItem, int(item_id))
            if item:
                item.sort_order = index
        db.session.commit()
        return jsonify(success=True)
    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, message=str(e)), 500

# (既存のAPIは省略)
# ...

# --- データベース初期化コマンド ---
@app.cli.command("init-db")
def init_db_command():
    with app.app_context():
        db.create_all() # drop_allを削除して既存データを保持
        # ユーザーが存在しない場合のみ作成
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin')
            admin_user.set_password('password123')
            db.session.add(admin_user)
            print("管理者アカウントを作成しました: admin / password123")
        
        # テーブルが存在しない場合のみ作成
        if Table.query.count() == 0:
            db.session.add_all([Table(name=f'{i}番テーブル') for i in range(1, 6)])
            print("サンプルテーブルを作成しました。")
        
        db.session.commit()
        print("データベースの初期化・更新が完了しました。")

# (以降のコードは変更なし)