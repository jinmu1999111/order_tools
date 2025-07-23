import os
import datetime
import secrets
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func, desc
import pytz

# --- アプリケーションとデータベースの初期設定 ---
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

# RenderのDATABASE_URL形式に対応しつつ、ローカルでのテストも考慮
db_url = os.environ.get('DATABASE_URL', 'sqlite:///instance/test.db')
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(hours=8)

# ローカルでSQLiteを使用する場合のinstanceフォルダ作成
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

class Table(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    status = db.Column(db.String(20), default='available')
    current_session_id = db.Column(db.String(100))
    guest_count = db.Column(db.Integer, default=0)
    x = db.Column(db.Float, default=0.0)
    y = db.Column(db.Float, default=0.0)
    orders = db.relationship('Order', backref='table', lazy='dynamic', cascade="all, delete-orphan")

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(100), nullable=False)
    item_price = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='pending')
    timestamp = db.Column(db.DateTime, default=lambda: datetime.datetime.now(JST))
    table_id = db.Column(db.Integer, db.ForeignKey('table.id'), nullable=False)
    session_id = db.Column(db.String(100))
    notified = db.Column(db.Boolean, default=False)

class QRToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(100), unique=True, nullable=False)
    table_name = db.Column(db.String(100))
    guest_count = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=lambda: datetime.datetime.now(JST))
    used = db.Column(db.Boolean, default=False)
    def is_valid(self):
        if self.used: return False
        expiry = self.created_at + datetime.timedelta(minutes=30)
        return datetime.datetime.now(JST) < expiry

# --- デコレータ ---
def require_qr_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'qr_token' in session:
            token = QRToken.query.filter_by(token=session['qr_token']).first()
            if token and token.is_valid():
                return f(*args, **kwargs)
        if current_user.is_authenticated:
             return f(*args, **kwargs)
        flash('このページにアクセスするにはQRコードのスキャンが必要です。', 'warning')
        return redirect(url_for('index'))
    return decorated_function

# --- ログインマネージャー ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- メインルート ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/qr/<token>')
def qr_auth(token):
    qr_token = QRToken.query.filter_by(token=token).first()
    if not qr_token or not qr_token.is_valid():
        flash('QRコードが無効か期限切れです。', 'danger')
        return redirect(url_for('index'))
    
    session['qr_token'] = token
    table = Table.query.filter_by(name=qr_token.table_name).first()
    if not table:
        table = Table(name=qr_token.table_name, status='occupied', current_session_id=token, guest_count=qr_token.guest_count)
        db.session.add(table)
    else:
        table.status = 'occupied'
        table.current_session_id = token
        table.guest_count = qr_token.guest_count
    qr_token.used = True
    db.session.commit()
    return redirect(url_for('table_menu', table_id=table.id))

@app.route('/table/<int:table_id>')
@require_qr_token
def table_menu(table_id):
    table = db.session.get(Table, table_id)
    if not table: abort(404)
    menu_items = MenuItem.query.filter_by(active=True).all()
    categorized_menu = {}
    for item in menu_items:
        categorized_menu.setdefault(item.category, []).append(item)
    return render_template('table_menu.html', table=table, categorized_menu=categorized_menu)

# --- 管理者ページ ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user, remember=('remember_me' in request.form))
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        flash('ユーザー名またはパスワードが違います。', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/kitchen')
@login_required
def kitchen():
    return render_template('kitchen.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/admin/menu')
@login_required
def admin_menu():
    return render_template('admin_menu.html', menu_items=MenuItem.query.all())

@app.route('/admin/menu/add', methods=['POST'])
@login_required
def add_menu_item():
    db.session.add(MenuItem(name=request.form['name'], price=request.form['price'], category=request.form['category']))
    db.session.commit()
    flash('メニューを追加しました。', 'success')
    return redirect(url_for('admin_menu'))

@app.route('/admin/tables')
@login_required
def admin_tables():
    return render_template('admin_tables.html', tables=Table.query.all())

@app.route('/admin/tables/add', methods=['POST'])
@login_required
def add_table():
    name = request.form.get('name')
    if name and not Table.query.filter_by(name=name).first():
        db.session.add(Table(name=name))
        db.session.commit()
        flash(f'テーブル「{name}」を追加しました。', 'success')
    else:
        flash('その名前は既に使用されているか、空です。', 'danger')
    return redirect(url_for('admin_tables'))
    
@app.route('/admin/history')
@login_required
def admin_history():
    return render_template('admin_history.html', tables=Table.query.all())

@app.route('/admin/guidance')
@login_required
def admin_guidance():
    return render_template('admin_guidance.html')

# --- APIエンドポイント ---

@app.route('/api/order/submit', methods=['POST'])
@require_qr_token
def submit_order():
    data = request.get_json()
    table = db.session.get(Table, data.get('table_id'))
    if not table: return jsonify(success=False, message="テーブル情報がありません。"), 400
    for item_id, item_data in data.get('items', {}).items():
        menu_item = db.session.get(MenuItem, int(item_id))
        if menu_item:
            menu_item.popularity_count += item_data['quantity']
            for _ in range(item_data['quantity']):
                db.session.add(Order(item_name=item_data['name'], item_price=item_data['price'], table_id=table.id, session_id=session.get('qr_token')))
    db.session.commit()
    return jsonify(success=True)

@app.route('/api/stats/dashboard')
@login_required
def api_stats_dashboard():
    today = datetime.datetime.now(JST).date()
    start_of_day = datetime.datetime.combine(today, datetime.time.min, tzinfo=JST)
    sales = db.session.query(func.sum(Order.item_price)).filter(Order.timestamp >= start_of_day).scalar() or 0
    count = Order.query.filter(Order.timestamp >= start_of_day).count()
    tables = {row[0]: row[1] for row in db.session.query(Table.status, func.count(Table.id)).group_by(Table.status).all()}
    popular = [{'name': i.name, 'count': i.popularity_count} for i in MenuItem.query.order_by(MenuItem.popularity_count.desc()).limit(5).all()]
    return jsonify(today_sales=sales, order_count=count, table_stats=tables, popular_items=popular)

@app.route('/api/dashboard/sales')
@login_required
def api_dashboard_sales():
    period = request.args.get('period', 'daily')
    labels, sales = [], []
    today = datetime.date.today()
    if period == 'daily':
        for i in range(6, -1, -1):
            day = today - datetime.timedelta(days=i)
            day_start = datetime.datetime.combine(day, datetime.time.min, tzinfo=JST)
            day_end = datetime.datetime.combine(day, datetime.time.max, tzinfo=JST)
            daily_total = db.session.query(func.sum(Order.item_price)).filter(Order.timestamp.between(day_start, day_end)).scalar() or 0
            labels.append(day.strftime('%m/%d'))
            sales.append(daily_total)
    else: # monthly
        for i in range(5, -1, -1):
            # 月の初日を計算
            target_month_start_naive = (today.replace(day=1) - datetime.timedelta(days=i*30)).replace(day=1)
            target_month_start = JST.localize(datetime.datetime.combine(target_month_start_naive, datetime.time.min))
            # 翌月の初日を計算
            next_month_start_naive = (target_month_start_naive + datetime.timedelta(days=32)).replace(day=1)
            next_month_start = JST.localize(datetime.datetime.combine(next_month_start_naive, datetime.time.min))
            
            monthly_total = db.session.query(func.sum(Order.item_price)).filter(Order.timestamp >= target_month_start, Order.timestamp < next_month_start).scalar() or 0
            labels.append(target_month_start.strftime('%Y/%m'))
            sales.append(monthly_total)
    return jsonify(labels=labels, sales=sales)

@app.route('/api/history/orders')
@login_required
def api_history_orders():
    orders = db.session.query(Order, Table.name).join(Table).order_by(Order.timestamp.desc()).all()
    return jsonify(orders=[{'id': o.id, 'table_name': t, 'item_name': o.item_name, 'item_price': o.item_price, 'status': o.status, 'timestamp': o.timestamp.isoformat()} for o, t in orders])

@app.route('/api/menu/update_full', methods=['POST'])
@login_required
def api_menu_update_full():
    data = request.json
    item = db.session.get(MenuItem, data['id'])
    if not item: return jsonify(success=False), 404
    item.name, item.price, item.category = data['name'], data['price'], data['category']
    db.session.commit()
    return jsonify(success=True)

@app.route('/api/menu/import', methods=['POST'])
@login_required
def api_menu_import():
    items = request.json.get('items', [])
    for item_data in items:
        db.session.add(MenuItem(name=item_data['name'], price=item_data['price'], category=item_data['category']))
    db.session.commit()
    return jsonify(success=True, count=len(items))

@app.route('/api/tables/save_positions', methods=['POST'])
@login_required
def api_save_table_positions():
    for table_data in request.json.get('tables', []):
        table = db.session.get(Table, int(table_data['id']))
        if table: table.x, table.y = table_data['x'], table_data['y']
    db.session.commit()
    return jsonify(success=True)

@app.route('/admin/menu/delete/<int:item_id>', methods=['GET'])
@login_required
def delete_menu_item(item_id):
    item = db.session.get(MenuItem, item_id)
    if item:
        db.session.delete(item)
        db.session.commit()
        return jsonify(success=True)
    return jsonify(success=False), 404

@app.route('/admin/menu/toggle/<int:item_id>', methods=['GET'])
@login_required
def toggle_menu_item(item_id):
    item = db.session.get(MenuItem, item_id)
    if item:
        item.active = not item.active
        db.session.commit()
        return jsonify(success=True)
    return jsonify(success=False), 404

@app.route('/admin/tables/delete/<int:table_id>', methods=['GET'])
@login_required
def delete_table(table_id):
    table = db.session.get(Table, table_id)
    if table:
        db.session.delete(table)
        db.session.commit()
        return jsonify(success=True)
    return jsonify(success=False), 404

# --- データベース初期化コマンド ---
@app.cli.command("init-db")
def init_db_command():
    """データベースをクリアし、初期データを投入します。"""
    db.drop_all()
    db.create_all()
    admin_user = User(username='admin', is_admin=True)
    admin_user.set_password('password123')
    db.session.add(admin_user)
    db.session.add_all([Table(name=f'{i}番テーブル') for i in range(1, 6)])
    db.session.add_all([
        MenuItem(name='シーザーサラダ', price=800, category='前菜'),
        MenuItem(name='ステーキ', price=2500, category='メイン'),
        MenuItem(name='カルボナーラ', price=1200, category='パスタ'),
    ])
    db.session.commit()
    print("データベースが初期化されました。")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', is_admin=True)
            admin_user.set_password('password123')
            db.session.add(admin_user)
            db.session.commit()
            print("Default admin user created.")
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
